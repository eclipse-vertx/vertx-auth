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

/** @module vertx-auth-jdbc-js/jdbc_auth */
var utils = require('vertx-js/util/utils');
var User = require('vertx-auth-common-js/user');
var JDBCClient = require('vertx-jdbc-js/jdbc_client');
var Vertx = require('vertx-js/vertx');
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JJDBCAuth = Java.type('io.vertx.ext.auth.jdbc.JDBCAuth');

/**

 @class
*/
var JDBCAuth = function(j_val) {

  var j_jDBCAuth = j_val;
  var that = this;
  AuthProvider.call(this, j_val);

  /**

   @public
   @param arg0 {Object} 
   @param arg1 {function} 
   */
  this.authenticate = function(arg0, arg1) {
    var __args = arguments;
    if (__args.length === 2 && (typeof __args[0] === 'object' && __args[0] != null) && typeof __args[1] === 'function') {
      j_jDBCAuth["authenticate(io.vertx.core.json.JsonObject,io.vertx.core.Handler)"](utils.convParamJsonObject(arg0), function(ar) {
      if (ar.succeeded()) {
        arg1(utils.convReturnVertxGen(User, ar.result()), null);
      } else {
        arg1(null, ar.cause());
      }
    });
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Set the authentication query to use. Use this if you want to override the default authentication query.

   @public
   @param authenticationQuery {string} the authentication query 
   @return {JDBCAuth} a reference to this for fluency
   */
  this.setAuthenticationQuery = function(authenticationQuery) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(JDBCAuth, j_jDBCAuth["setAuthenticationQuery(java.lang.String)"](authenticationQuery));
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Set the roles query to use. Use this if you want to override the default roles query.

   @public
   @param rolesQuery {string} the roles query 
   @return {JDBCAuth} a reference to this for fluency
   */
  this.setRolesQuery = function(rolesQuery) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(JDBCAuth, j_jDBCAuth["setRolesQuery(java.lang.String)"](rolesQuery));
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Set the permissions query to use. Use this if you want to override the default permissions query.

   @public
   @param permissionsQuery {string} the permissions query 
   @return {JDBCAuth} a reference to this for fluency
   */
  this.setPermissionsQuery = function(permissionsQuery) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(JDBCAuth, j_jDBCAuth["setPermissionsQuery(java.lang.String)"](permissionsQuery));
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Set the role prefix to distinguish from permissions when checking for isPermitted requests.

   @public
   @param rolePrefix {string} a Prefix e.g.: "role:" 
   @return {JDBCAuth} a reference to this for fluency
   */
  this.setRolePrefix = function(rolePrefix) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(JDBCAuth, j_jDBCAuth["setRolePrefix(java.lang.String)"](rolePrefix));
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Compute the hashed password given the unhashed password and the salt
  
   The implementation relays to the JDBCHashStrategy provided.

   @public
   @param password {string} the unhashed password 
   @param salt {string} the salt 
   @return {string} the hashed password
   */
  this.computeHash = function(password, salt) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'string') {
      return j_jDBCAuth["computeHash(java.lang.String,java.lang.String)"](password, salt);
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Compute a salt string.
  
   The implementation relays to the JDBCHashStrategy provided.

   @public

   @return {string} a non null salt value
   */
  this.generateSalt = function() {
    var __args = arguments;
    if (__args.length === 0) {
      return j_jDBCAuth["generateSalt()"]();
    } else throw new TypeError('function invoked with invalid arguments');
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_jDBCAuth;
};

JDBCAuth._jclass = utils.getJavaClass("io.vertx.ext.auth.jdbc.JDBCAuth");
JDBCAuth._jtype = {
  accept: function(obj) {
    return JDBCAuth._jclass.isInstance(obj._jdel);
  },
  wrap: function(jdel) {
    var obj = Object.create(JDBCAuth.prototype, {});
    JDBCAuth.apply(obj, arguments);
    return obj;
  },
  unwrap: function(obj) {
    return obj._jdel;
  }
};
JDBCAuth._create = function(jdel) {
  var obj = Object.create(JDBCAuth.prototype, {});
  JDBCAuth.apply(obj, arguments);
  return obj;
}
/**
 Create a JDBC auth provider implementation

 @memberof module:vertx-auth-jdbc-js/jdbc_auth
 @param vertx {Vertx} 
 @param client {JDBCClient} the JDBC client instance 
 @return {JDBCAuth} the auth provider
 */
JDBCAuth.create = function(vertx, client) {
  var __args = arguments;
  if (__args.length === 2 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'object' && __args[1]._jdel) {
    return utils.convReturnVertxGen(JDBCAuth, JJDBCAuth["create(io.vertx.core.Vertx,io.vertx.ext.jdbc.JDBCClient)"](vertx._jdel, client._jdel));
  } else throw new TypeError('function invoked with invalid arguments');
};

module.exports = JDBCAuth;