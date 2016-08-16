#!/usr/bin/env python3

import os
import cherrypy
import ldap3
import time
from string import Template
from email.mime.text import MIMEText
import subprocess
import argparse

class JSONHTTPError(cherrypy.HTTPError):

    def __init__(self, status=500, message=None, name=None):
        cherrypy.HTTPError.__init__(self, status, message)

        self.message = message or http.client.response[status]
        self.name = name or self.__class__.__name__

    def set_response(self):
        import json
        cherrypy.HTTPError.set_response(self)
        response = cherrypy.serving.response
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Length"] = None
        response.body = json.dumps({
            "name": self.name,
            "message": self.message
        }).encode("utf-8")


class BadRequestError(JSONHTTPError):
    pass

def no_index():
    """Tool to disable slash redirect for indexes"""
    cherrypy.request.is_index = False
cherrypy.tools.no_index = cherrypy.Tool('before_handler', no_index)

def restrict_methods(methods):
    """Tool for restricting to a certain set of allowed HTTP methods"""
    if not cherrypy.request.method in methods:
        raise JSONHTTPError(405)
cherrypy.tools.restrict_methods = cherrypy.Tool('before_handler', restrict_methods)


class Helpers:
    """Useful helper functions for the main classes"""

    @staticmethod
    def get_user_ldap_connection(config, username, password):
        """Get an LDAP connection with bind to user DN. This verifies the
        credentials and is used to read user data."""

        server = ldap3.Server(config["ldap.uri"])
        cherrypy.log(config["ldap.bind_template"] % username)
        conn = ldap3.Connection(server, config["ldap.bind_template"] % ldap3.utils.conv.escape_bytes(username), password)
        if not conn.bind():
            conn.unbind()
            return None
        return conn
    
    @staticmethod
    def get_admin_ldap_connection(config):
        """Get an LDAP connection with administration rights. This is used for
        changing data."""

        server = ldap3.Server(config["ldap.uri"])
        conn = ldap3.Connection(server, config["ldap.admin_bind"] , config["ldap.admin_pw"])
        if not conn.bind():
            conn.unbind()
            return None
        return conn

    @staticmethod
    def validate_string(string, min_length=1, max_length=256, type_mail=False, type_single_line=False, type_safe_ascii=False, name=None):
        """Basic string validation"""
        
        prefix = "\"%s\" " % name if name else ""
        if string == None: raise ValueError(prefix + "invalid")
        if min_length > 0 and len(string) == 0: raise ValueError(prefix + "cannot be empty")
        if len(string) < min_length: raise ValueError(prefix + "too short")
        if len(string) > max_length: raise ValueError(prefix + "too long")
        if type_safe_ascii or type_mail:
            for c in string:
                if ord(c) < 32 or ord(c) > 126: raise ValueError(prefix + "invalid characters")
        if type_mail and not '@' in string: raise ValueError(prefix + "not a valid mail address")
        if (type_single_line or type_mail) and '\n' in string: raise ValueError(prefix + "not a single line")

    @staticmethod
    def get_profile(config, conn, userid):
        """Get relevant profile attributes from LDAP"""
        
        attribs = ['displayName', 'mail', 'uidNumber', 'description', 'modifyTimestamp']
        mandatory_attribs = ['displayName', 'mail', 'uidNumber', 'modifyTimestamp']
        try:
            conn.search(config["ldap.base_dn"],
                    config["ldap.search_filter"] %ldap3.utils.conv.escape_bytes(userid),
                    attributes=attribs)
        except ldap3.LDAPException as ex:
            raise JSONHTTPError(500, "Unable to get user profile")
        
        if len(conn.entries) == 0:
            raise JSONHTTPError(400, "Cannot find user")
            
        for a in mandatory_attribs:
            if not a in conn.entries[0]:
                raise JSONHTTPError(500, "Invalid user profile")

        entry = conn.entries[0].entry_get_attributes_dict()
        
        if not entry.get("description"):
            entry["description"] = [("")]
        
        return entry


@cherrypy.popargs("userid")
class Users:
    """User-specific operations"""

    @cherrypy.expose
    @cherrypy.tools.restrict_methods(methods=["POST", "GET"])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def profile(self, userid):
        """Get or update profile"""
        
        if userid != cherrypy.request.login:
            raise JSONHTTPError(401, "Request does not match authentification")

        config = cherrypy.request.config
        conn = cherrypy.request.ldap_connection
        if cherrypy.request.method == "GET":
            entry = Helpers.get_profile(config, conn, userid)
            
            # XXX: remove gnumpf.tk address from mails
            mail_addresses = list(filter(lambda x: not x.endswith("gnumpf.tk"), entry["mail"]))
            
            response = {
                "display_name": entry["displayName"][0],
                "mail": mail_addresses[0],
                "description": entry["description"][0],
                "uid": int(entry["uidNumber"][0]),
                "last_change": ldap3.protocol.formatters.formatters.format_time(entry["modifyTimestamp"][0].encode("ASCII")).timestamp(),
            }
            
            return response

        elif cherrypy.request.method == "POST":
            req = cherrypy.request.json
            
            # do some basic validation
            try:
                Helpers.validate_string(req.get("display_name"), name="display_name")
                Helpers.validate_string(req.get("mail"), type_mail=True, type_single_line=True, name="mail")
                Helpers.validate_string(req.get("description"), type_single_line=True, min_length=0, name="description")
            except ValueError as v:
                raise JSONHTTPError(400, str(v))
            
            # we need the current profile to update the mail
            entry = Helpers.get_profile(config, conn, userid)
            
            # XXX: remove gnumpf.tk address from mails
            mail_addresses = list(filter(lambda x: not x.endswith("gnumpf.tk"), entry["mail"]))
            old_mail_address = mail_addresses[0]

            conn = Helpers.get_admin_ldap_connection(config)
            if not conn:
                raise JSONHTTPError(500, "Failed to connect to directory")

            operations = {
                'displayName': [(ldap3.MODIFY_REPLACE, [req.get("display_name")])],
                'description': [(ldap3.MODIFY_REPLACE, [req.get("description")] if len(req.get("description")) else [])],
            };
            
            # LDAP doesn't like if we change as non-op.
            if old_mail_address != req.get("mail"):
                operations["mail"] = [(ldap3.MODIFY_ADD, [req.get("mail")]),
                                      (ldap3.MODIFY_DELETE, [old_mail_address])];

            try:
                conn.modify(config["ldap.bind_template"] %ldap3.utils.conv.escape_bytes(userid), operations);
            except ldap3.LDAPException as ex:
                cherrypy.log(str(ex))
                raise JSONHTTPError(500, "Unable to update profile entry")
            
            return True

    @cherrypy.expose
    @cherrypy.tools.restrict_methods(methods=["POST"])
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def password(self, userid):
        """Set new password"""

        config = cherrypy.request.config
        req = cherrypy.request.json
        
        # do some basic validation
        try:
            Helpers.validate_string(req.get("password"), min_length=6, type_single_line=True, type_safe_ascii=True)
        except ValueError as v:
            raise JSONHTTPError(400, str(v))

        conn = Helpers.get_admin_ldap_connection(config)
        if not conn:
            raise JSONHTTPError(500, "Failed to connect to directory service")
        
        try:
            conn.extend.standard.modify_password(config["ldap.bind_template"] %ldap3.utils.conv.escape_bytes(userid), None, req.get("password"))
        except ldap3.LDAPException as ex:
            raise JSONHTTPError(500, "Unable to change password")

        return True

    @cherrypy.expose()
    @cherrypy.tools.no_index()
    @cherrypy.tools.restrict_methods(methods=["GET"])
    @cherrypy.tools.json_out()
    def index(self, userid):
        """Verify login"""

        return True
       

@cherrypy.popargs("ticketid")
class Tickets:
    """Redeem recovery tickets"""
    
    def __init__(self):
        self.tickets = {}
    
    def send_ticket_mail(self, ticket, userid, mail_to):
        config = cherrypy.request.config

        mail_template = Template(open(config["recover.mail_template"]).read())
        mail_body = mail_template.substitute(
            user=userid,
            ticketid=ticket,
            ticket_timeout=config["recover.ticket_timeout_mins"]
        )
        
        msg = MIMEText(mail_body)
        msg["Subject"] = config["recover.mail_subject"]
        msg["From"] = config["recover.mail_from"]
        msg["To"] = mail_to
        

        if config.get("recover.debug") == True:
            print(msg)
        else:
            # use sendmail to send it out
            sendmail_path = config["recover.sendmail_path"]
            p = subprocess.Popen([sendmail_path, "-f", config["recover.mail_from"],
                                "-t", "-oi"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            p.communicate(str(msg).encode("ASCII"))

    @cherrypy.expose()
    @cherrypy.tools.no_index()
    @cherrypy.tools.restrict_methods(methods=["POST", "GET"])
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def index(self, ticketid=None):
        """Handle ticket redeem and generation."""

        config = cherrypy.request.config
        
        if ticketid == None and cherrypy.request.method == "POST":
            req = cherrypy.request.json
            
            # do some basic validation
            try:
                Helpers.validate_string(req.get("username"), type_safe_ascii=True)
                Helpers.validate_string(req.get("mail"), type_mail=True, type_single_line=True)
            except ValueError as v:
                raise JSONHTTPError("400", "Invalid parameters")

            conn = Helpers.get_admin_ldap_connection(config)
            if not conn:
                raise JSONHTTPError("500", "Failed to connect to directory service")
            
            entry = Helpers.get_profile(config, conn, req.get("username"))
            if not (req.get("mail") in entry["mail"]):
                raise JSONHTTPError("400", "User not found")

            # ticket generation
            ticketstr = ''.join([ "%02x"%x for x in bytes(os.urandom(16)) ])
            self.tickets[ticketstr] = (req.get("username"), time.time())
            
            # finally send mail
            self.send_ticket_mail(ticketstr, req.get("username"), req.get("mail"))
            
            return True
            
        elif ticketid != None and cherrypy.request.method == "GET":
            # validate ticketid
            try:
                Helpers.validate_string(ticketid, type_safe_ascii=True, min_length=32, max_length=32)
            except ValueError as v:
                raise JSONHTTPError(400, "Invalid ticket")
            
            # purge old tickets
            ticket_timeout = int(config["recover.ticket_timeout_mins"]) * 60
            self.tickets = dict(filter(lambda k: (time.time() - k[1][1]) < ticket_timeout, self.tickets.items()))

            # ticket might be unknown or deleted by purge
            ticket = self.tickets.get(ticketid)
            if ticket == None:
                raise JSONHTTPError(400)

            # finally, generate new random password
            conn = Helpers.get_admin_ldap_connection(config)
            if not conn:
                raise JSONHTTPError(500, "Failed to connect to directory service")
            
            new_password = None
            username = ticket[0]
            try:
                new_password = conn.extend.standard.modify_password(config["ldap.bind_template"] % username, None, None)
            except ldap3.LDAPException as ex:
                raise JSONHTTPError(500, "Unable to generate new password")
                
            # delete ticket
            del self.tickets[ticketid]

            return { "username": username, "password": new_password }

        else:
            raise JSONHTTPError(400);


class Api:
    def __init__(self):
        self.users = Users()
        self.tickets = Tickets()


class Root:
    def check_login(self, realm, username, password):
        if realm != "earth":
            return False
        conn = Helpers.get_user_ldap_connection(cherrypy.request.config, username, password)
        if conn:
            cherrypy.request.ldap_connection = conn
            return True

        return False
    
    def __init__(self):
        self.api = Api()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ldap-selfservice")
    parser.add_argument("--debug", "-d", action="store_true", help="debug mode")
    args = parser.parse_args()

    root = Root()

    global_config = {
        'server.socket_host': "::1",
        'server.socket_port': 1234,
        'tools.proxy.on': True,
    }

    app_config = {
        '/api/users': {
            'tools.auth_basic.on': True,
            'tools.auth_basic.realm': 'earth',
            'tools.auth_basic.checkpassword': root.check_login,
        },
        '/': {
            'tools.staticdir.root': os.path.abspath(os.getcwd()),
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './static',
            'tools.staticdir.index': 'index.html',
        },
    }
    
    if args.debug == False:
        cherrypy.config.update(cherrypy.config.environments["production"])

    cherrypy.config.update("global.conf")
    cherrypy.quickstart(root, '/', app_config)
