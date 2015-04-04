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

/** @module vertx-auth-js/auth_provider */
var utils = require('vertx-js/util/utils');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JAuthProvider = io.vertx.ext.auth.AuthProvider;

/**
 This interface is implemented by auth providers which provide the actual auth functionality -
 e.g. we have a implementation which uses Apache Shiro.
 <p>
 If you wish to use the auth service with other providers, implement this interface for your provider.

 @class
*/
var AuthProvider = function(j_val) {

  var j_authProvider = j_val;
  var that = this;

  /**
   Handle the actual login

   @public
   @param principal {Object} represents the unique id (e.g. username) of the user being logged in 
   @param credentials {Object} the credentials - this can contain anything your provider expects, e.g. password 
   @param resultHandler {function} - this must return a failed result if login fails and it must return a succeeded result if the login succeeds 
   */
  this.login = function(principal, credentials, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'object' && typeof __args[2] === 'function') {
      j_authProvider["login(io.vertx.core.json.JsonObject,io.vertx.core.json.JsonObject,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), utils.convParamJsonObject(credentials), function(ar) {
      if (ar.succeeded()) {
        resultHandler(null, null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  /**
   Handle whether a principal has a role

   @public
   @param principal {Object} represents the unique id (e.g. username) of the user being logged in 
   @param role {string} the role 
   @param resultHandler {function} this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the role, or `false` if they do not have the role. 
   */
  this.hasRole = function(principal, role, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authProvider["hasRole(io.vertx.core.json.JsonObject,java.lang.String,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), role, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  /**
   Handle whether a principal has a permission

   @public
   @param principal {Object} represents the unique id (e.g. username) of the user being logged in 
   @param permission {string} the permission 
   @param resultHandler {function} this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the permission, or `false` if they do not have the permission. 
   */
  this.hasPermission = function(principal, permission, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authProvider["hasPermission(io.vertx.core.json.JsonObject,java.lang.String,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), permission, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_authProvider;
};

// We export the Constructor function
module.exports = AuthProvider;