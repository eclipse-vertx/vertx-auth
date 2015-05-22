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

/** @module vertx-auth-js/user */
var utils = require('vertx-js/util/utils');
var AuthProvider = require('vertx-auth-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JUser = io.vertx.ext.auth.User;

/**
 Represents an authenticate User and contains operations to authorise the user, using a role/permission
 based model.
 <p>
 Please consult the documentation for a detailed explanation.

 @class
*/
var User = function(j_val) {

  var j_user = j_val;
  var that = this;

  /**
   Does the user have the specified role?

   @public
   @param role {string} the role 
   @param resultHandler {function} handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the role or `false` otherwise. 
   @return {User} the User to enable fluent use
   */
  this.hasRole = function(role, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_user["hasRole(java.lang.String,io.vertx.core.Handler)"](role, function(ar) {
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
   @param permission {string} the permission 
   @param resultHandler {function} handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the permission or `false` otherwise. 
   @return {User} the User to enable fluent use
   */
  this.hasPermission = function(permission, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_user["hasPermission(java.lang.String,io.vertx.core.Handler)"](permission, function(ar) {
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
   Does the user have all the specified roles?

   @public
   @param roles {Array.<string>} the set of roles 
   @param resultHandler {function} handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have all the roles or `false` otherwise. 
   @return {User} the User to enable fluent use
   */
  this.hasRoles = function(roles, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'object' && __args[0] instanceof Array && typeof __args[1] === 'function') {
      j_user["hasRoles(java.util.Set,io.vertx.core.Handler)"](utils.convParamSetBasicOther(roles), function(ar) {
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
   Does the user have all the specified permissions?

   @public
   @param permissions {Array.<string>} the set of permissions 
   @param resultHandler {function} handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have all the permissions or `false` otherwise. 
   @return {User} the User to enable fluent use
   */
  this.hasPermissions = function(permissions, resultHandler) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'object' && __args[0] instanceof Array && typeof __args[1] === 'function') {
      j_user["hasPermissions(java.util.Set,io.vertx.core.Handler)"](utils.convParamSetBasicOther(permissions), function(ar) {
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
   The User object will cache any roles or permissions that it knows it has to avoid hitting the
   underlying auth provider each time.  Use this method if you want to clear this cache.

   @public

   @return {User} the User to enable fluent use
   */
  this.clearCache = function() {
    var __args = arguments;
    if (__args.length === 0) {
      j_user["clearCache()"]();
      return that;
    } else utils.invalidArgs();
  };

  /**
   Get the underlying principal for the User. What this actually returns depends on the implementation.
   For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
   <pre>
     {
       "username", "tim"
     }
   </pre>

   @public

   @return {Object} 
   */
  this.principal = function() {
    var __args = arguments;
    if (__args.length === 0) {
      return utils.convReturnJson(j_user["principal()"]());
    } else utils.invalidArgs();
  };

  /**
   Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
   after it has been deserialized.

   @public
   @param authProvider {AuthProvider} the AuthProvider - this must be the same type of AuthProvider that originally created the User 
   */
  this.setAuthProvider = function(authProvider) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      j_user["setAuthProvider(io.vertx.ext.auth.AuthProvider)"](authProvider._jdel);
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_user;
};

// We export the Constructor function
module.exports = User;