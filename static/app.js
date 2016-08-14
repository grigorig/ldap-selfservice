'use strict';

angular.module('LoginApp', ['ngRoute'])
    .config(function($routeProvider) {
      $routeProvider
        .when('/', { templateUrl: 'login.tpl.html' })
        .when('/profile', { templateUrl: 'profile.tpl.html' })
        .when('/recover', { templateUrl: 'recovery.tpl.html' })
        .otherwise({ redirectTo: '/' });
    })
    
    // MasterCtrl handles changes to the overall page layout and modals
    .controller('MasterCtrl', function($scope, ProfileManager) {
        $scope.pm = ProfileManager;
        $scope.show_modal = false;
        $scope.$on("titleChanged", function(event, new_title) {
            $scope.title = new_title;
        });
        $scope.$on("showModal", function(event, title, msg, err, post) {
            $scope.modal_title = title;
            $scope.modal_msg = msg;
            $scope.modal_err_msg = err;
            $scope.modal_post_msg = post;
            $scope.show_modal = true;
        });
    })
  
    // LoginController - Handle login form
    // Verifies credentials with ProfileManager
    .controller('LoginCtrl', function($scope, $location, $http, $log, $window, $timeout, $routeParams, ProfileManager) {
        $scope.pm = ProfileManager;
        $scope.busy = false;
        $scope.$emit("titleChanged", "Login");
        
        var setStatus = function(status) {
            $scope.status_message = status;
            $timeout(function() { $scope.status_message = ""; }, 5000);
        };
        
        if ($routeParams["ticket"] != undefined) {
            $scope.busy = true;
            $scope.pm.redeemReset($routeParams["ticket"]).then(function(params) {
                if (params == null) {
                    $scope.$emit("showModal", "Ticket Reedem Failed", "Failed to redeem a password reset ticket. The ticket may have timed out. Please request a new ticket and try again.");
                    $location.search({})
                    $scope.busy = false;
                    return;
                }
                $scope.pm.login(params.username, params.password).then(function(status) {
                    if (status == true) {
                        $location.path("/profile");
                    } else {
                        $scope.$emit("showModal", "Ticket Reedem Failed", "Failed to login after redeeming password reset ticket. This should not happen. Please request a new ticket and try again.");
                        $location.search({})
                        $scope.busy = false;
                    }
                });
            });
        }

        $scope.doLogin = function() {
            $scope.busy = true;
            $scope.status_message = "";
            $scope.pm.login($scope.username, $scope.password).then(function(status) {
                if (status == true) {
                    $location.url("/profile");
                } else {
                    setStatus("Login failed.");
                    $scope.busy = false;
                    document.getElementById("login-username").focus();
                }
            });
        };
    })

    .controller('ProfileCtrl', function($scope, $location, $timeout, $routeParams, ProfileManager) {
        $scope.pm = ProfileManager;
        $scope.busy = true;
        $scope.$emit("titleChanged", "Edit " + $scope.pm.getUsername());
        $scope.model = {};

        if ($routeParams["ticket"] != undefined) {
            $scope.$emit("showModal", "Ticket Redeemed", "Password reset ticket was redeemed. Please change the password now.");
            //$location.search({})
        }

        var loadProfile = function() {
            $scope.pm.get_profile().then(function(profile_data) {
                if (profile_data == null) {
                    $scope.$emit("showModal", "Error", "Failed to load profile. Please log out and try again.");
                    return;
                }
                $scope.model = profile_data;
                $scope.model.username = $scope.pm.getUsername();
                $scope.busy = false;
            });
        };
        
        // not authenticated? back to login
        if (!$scope.pm.isAuthenticated()) {
            $location.url("/");
        } else {
            loadProfile();
        }

        // logout if the page is left
        $scope.$on("$routeChangeStart", function(event) {
            $scope.pm.logout();
        });
        
        $scope.formatDate = function(unixtime) {
            var d = new Date(1000 * unixtime);
            return d.toLocaleString();
        };
        
        $scope.doSaveProfile = function() {
            $scope.busy = true;
            var profile_data = {
                display_name: $scope.model.display_name,
                mail: $scope.model.mail,
                description: $scope.model.description
            }; 
            $scope.pm.set_profile(profile_data).then(function(status) {
                if (status == true) {
                    $scope.status_message_profile = "Saved.";
                    $timeout(function() { $scope.status_message_profile = ""; }, 5000);
                    loadProfile();
                    $scope.busy = false;
                } else {
                    $scope.busy = false;
                    $scope.$emit("showModal", "Error", "Failed to save profile. Please try again.");
                }
            });

        };

        $scope.doSavePassword = function() {
            $scope.busy = true;
            $scope.pm.set_password($scope.password_first).then(function(status) {
                if (status == true) {
                    $scope.status_message_pass = "Saved.";
                    $timeout(function() { $scope.status_message_pass = ""; }, 5000);
                    $scope.busy = false;
                } else {
                    $scope.busy = false;
                    $scope.$emit("showModal", "Error", "Failed to save password. Please try again.");
                }
            });
        };

        $scope.doLogout = function() {
            $scope.pm.logout();
            $location.url("/");
        };
    })
    
    // Password reset page
    .controller('RecoverCtrl', function($scope, $timeout, ProfileManager) {
        $scope.busy = false;
        $scope.status_message = "";
        $scope.pm = ProfileManager;
        $scope.$emit("titleChanged", "Password Reset");
        $scope.doReset = function() {
            $scope.busy = true;
            $scope.pm.requestReset($scope.username, $scope.mail).then(function success(response) {
                $scope.$emit("showModal", "Request Successful", "Your password reset request was successful. A reset ticket was sent to you. Please check your mail for further instructions.");
                $scope.busy = false;
            }, function error(response) {
                $scope.$emit("showModal", "Request Failed", "Your password reset request failed. Please verify mail and username and try again.");
                $scope.busy = false;
            });
        };
    })

    // ProfileManager factory object
    // This stores credentials between different pages
    .factory('ProfileManager', function($log, $http) {
        var username = null;
        var auth_header = null;
        var authenticated = false;
        
        var that = {
            login: function(_username, password) {
                var auth = "Basic " + btoa(_username + ":" + password)
                var httpConfig = {
                    method: "GET",
                    url: "/api/users/" + _username + "/",
                    headers: { "Authorization": auth }
                };
                return $http(httpConfig).then(function success(response) {
                    $log.debug("logged in as " + _username)
                    username = _username;
                    auth_header = auth;
                    authenticated = true;
                    return true;  
                }, function error(response) {
                    $log.debug("login failed");
                    return false;
                });
            },
            get_profile: function() {
                if (!authenticated)
                    return null;
                
                var httpConfig = {
                    method: "GET",
                    url: "/api/users/" + username + "/profile",
                    headers: { "Authorization": auth_header }
                };
                return $http(httpConfig).then(function success(response) {
                    return response.data;
                }, function error(response) {
                    return null;
                });
            },
            set_profile: function(profile_data) {
                if (!authenticated)
                    return false;
                
                var httpConfig = {
                    method: "POST",
                    url: "/api/users/" + username + "/profile",
                    headers: { "Authorization": auth_header,
                               "Content-Type": "application/json" },
                    data: profile_data
                };
                return $http(httpConfig).then(function success(response) {
                    return true;
                }, function error(response) {
                    return false;
                });
            },
            set_password: function(new_password) {
                if (!authenticated)
                    return false;
                
                var httpConfig = {
                    method: "POST",
                    url: "/api/users/" + username + "/password",
                    headers: { "Authorization": auth_header,
                               "Content-Type": "application/json" },
                    data: { password: new_password }
                };
                return $http(httpConfig).then(function success(response) {
                    that.login(username, new_password);
                    return true;
                }, function error(response) {
                    return false;
                });
            },
            getUsername: function() {
                return username;
            },
            isAuthenticated: function() {
                return authenticated;
            },
            logout: function() {
                username = null;
                auth_header = null;
                authenticated = false;
                $log.debug("logged out");
            },
            requestReset: function(req_username, req_mail) {
                var httpConfig = {
                    method: "POST",
                    url: "/api/tickets/",
                    headers: { "Content-Type": "application/json" },
                    data: { username: req_username,
                            mail: req_mail }
                };
                return $http(httpConfig);
            },
            redeemReset: function(ticketid) {
                var httpConfig = {
                    method: "GET",
                    url: "/api/tickets/" + ticketid,
                };
                return $http(httpConfig).then(function success(response) {
                    return response.data;
                }, function error(response) {
                    return null;
                });
            },
        };
        return that;
    })

    // more reliable autofocus
    // http://ericclemmons.com/angular/angular-autofocus-directive/
    .directive('autofocus', ['$document', function($document) {
     return {
        link: function($scope, $element, attrs) {
          setTimeout(function() {
            $element[0].focus();
          }, 100);
        }
      };
    }]);
