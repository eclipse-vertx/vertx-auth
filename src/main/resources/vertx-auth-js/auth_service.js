/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/** @module vertx-auth-js/auth_service */
var utils = require('vertx-js/util/utils');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JAuthService = io.vertx.ext.auth.AuthService;

/**
 Vert.x authentication and authorisation service.
 <p>
 Handles authentication and role/permission based authorisation.

 @class
*/
var AuthService = function(j_val) {

  var j_authService = j_val;
  var that = this;

  /**
   Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   provider is expecting. The default login ID timeout will be used.

   @public
   @param credentials {Object} the credentials 
   @param resultHandler {function} will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful. 
   @return {AuthService}
   */
  this.login = function(credentials, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'object' && typeof __args[1] === 'function') {
      j_authService.login(utils.convParamJsonObject(credentials), function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   provider is expecting. The specified login ID timeout will be used.

   @public
   @param credentials {Object} the credentials 
   @param timeout {number} the login timeout to use, in ms 
   @param resultHandler {function} will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful. 
   @return {AuthService}
   */
  this.loginWithTimeout = function(credentials, timeout, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] ==='number' && typeof __args[2] === 'function') {
      j_authService.loginWithTimeout(utils.convParamJsonObject(credentials), timeout, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Logout the user

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param resultHandler {function} will be called with success or failure 
   @return {AuthService}
   */
  this.logout = function(loginID, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_authService.logout(loginID, function(ar) {
      if (ar.succeeded()) {
        resultHandler(null, null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Refresh an existing login ID so it doesn't expire

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param resultHandler {function} will be called with success or failure 
   @return {AuthService}
   */
  this.refreshLoginSession = function(loginID, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_authService.refreshLoginSession(loginID, function(ar) {
      if (ar.succeeded()) {
        resultHandler(null, null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Does the user have the specified role?

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param role {string} the role 
   @param resultHandler {function} will be called with the result - true if has role, false if not 
   @return {AuthService}
   */
  this.hasRole = function(loginID, role, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'string' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authService.hasRole(loginID, role, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Does the user have the specified roles?

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param roles {Array.<string>} the set of roles 
   @param resultHandler {function} will be called with the result - true if has roles, false if not 
   @return {AuthService}
   */
  this.hasRoles = function(loginID, roles, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'string' && typeof __args[1] === 'object' && __args[1] instanceof Array && typeof __args[2] === 'function') {
      j_authService.hasRoles(loginID, utils.convParamSetBasicOther(roles), function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Does the user have the specified permission?

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param permission {string} the permission 
   @param resultHandler {function} will be called with the result - true if has permission, false if not 
   @return {AuthService}
   */
  this.hasPermission = function(loginID, permission, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'string' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authService.hasPermission(loginID, permission, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Does the user have the specified permissions?

   @public
   @param loginID {string} the login ID as provided by {@link #login}. 
   @param permissions {Array.<string>} the set of permissions 
   @param resultHandler {function} will be called with the result - true if has permissions, false if not 
   @return {AuthService}
   */
  this.hasPermissions = function(loginID, permissions, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'string' && typeof __args[1] === 'object' && __args[1] instanceof Array && typeof __args[2] === 'function') {
      j_authService.hasPermissions(loginID, utils.convParamSetBasicOther(permissions), function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
      return that;
    } else utils.invalidArgs();
  };

  /**
   Set the reaper period - how often to check for expired logins, in ms.

   @public
   @param reaperPeriod {number} the reaper period, in ms 
   @return {AuthService}
   */
  this.setReaperPeriod = function(reaperPeriod) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] ==='number') {
      j_authService.setReaperPeriod(reaperPeriod);
      return that;
    } else utils.invalidArgs();
  };

  /**
   Start the service

   @public

   */
  this.start = function() {
    var __args = arguments;
    if (__args.length === 0) {
      j_authService.start();
    } else utils.invalidArgs();
  };

  /**
   Stop the service

   @public

   */
  this.stop = function() {
    var __args = arguments;
    if (__args.length === 0) {
      j_authService.stop();
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_authService;
};

/**
 Create an auth service instance using the specified auth provider class name.

 @memberof module:vertx-auth-js/auth_service
 @param vertx {Vertx} the Vert.x instance 
 @param className {string} the fully qualified class name of the auth provider implementation class 
 @param config {Object} the configuration to pass to the provider 
 @return {AuthService} the auth service
 */
AuthService.createFromClassName = function(vertx, className, config) {
  var __args = arguments;
  if (__args.length === 3 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && typeof __args[2] === 'object') {
    return new AuthService(JAuthService.createFromClassName(vertx._jdel, className, utils.convParamJsonObject(config)));
  } else utils.invalidArgs();
};

/**
 Create a proxy to an auth service that is deployed somwehere on the event bus.

 @memberof module:vertx-auth-js/auth_service
 @param vertx {Vertx} the vert.x instance 
 @param address {string} the address on the event bus where the auth service is listening 
 @return {AuthService} the proxy
 */
AuthService.createEventBusProxy = function(vertx, address) {
  var __args = arguments;
  if (__args.length === 2 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string') {
    return new AuthService(JAuthService.createEventBusProxy(vertx._jdel, address));
  } else utils.invalidArgs();
};

// We export the Constructor function
module.exports = AuthService;