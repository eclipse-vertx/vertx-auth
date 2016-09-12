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

/** @module vertx-auth-oauth2-js/access_token */
var utils = require('vertx-js/util/utils');
var User = require('vertx-auth-common-js/user');
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JAccessToken = io.vertx.ext.auth.oauth2.AccessToken;

/**
 AccessToken extension to the User interface

 @class
*/
var AccessToken = function(j_val) {

  var j_accessToken = j_val;
  var that = this;
  User.call(this, j_val);

  /**

   @public
   @param arg0 {string} 
   @param arg1 {function} 
   @return {User}
   */
  this.isAuthorised = function(arg0, arg1) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_accessToken["isAuthorised(java.lang.String,io.vertx.core.Handler)"](arg0, function(ar) {
      if (ar.succeeded()) {
        arg1(ar.result(), null);
      } else {
        arg1(null, ar.cause());
      }
    });
      return that;
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**

   @public

   @return {User}
   */
  this.clearCache = function() {
    var __args = arguments;
    if (__args.length === 0) {
      j_accessToken["clearCache()"]();
      return that;
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**

   @public

   @return {Object}
   */
  this.principal = function() {
    var __args = arguments;
    if (__args.length === 0) {
      return utils.convReturnJson(j_accessToken["principal()"]());
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**

   @public
   @param arg0 {AuthProvider} 
   */
  this.setAuthProvider = function(arg0) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      j_accessToken["setAuthProvider(io.vertx.ext.auth.AuthProvider)"](arg0._jdel);
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Check if the access token is expired or not.

   @public

   @return {boolean}
   */
  this.expired = function() {
    var __args = arguments;
    if (__args.length === 0) {
      return j_accessToken["expired()"]();
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Refresh the access token

   @public
   @param callback {function} - The callback function returning the results. 
   @return {AccessToken}
   */
  this.refresh = function(callback) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'function') {
      j_accessToken["refresh(io.vertx.core.Handler)"](function(ar) {
      if (ar.succeeded()) {
        callback(null, null);
      } else {
        callback(null, ar.cause());
      }
    });
      return that;
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Revoke access or refresh token

   @public
   @param token_type {string} - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token". 
   @param callback {function} - The callback function returning the results. 
   @return {AccessToken}
   */
  this.revoke = function(token_type, callback) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'function') {
      j_accessToken["revoke(java.lang.String,io.vertx.core.Handler)"](token_type, function(ar) {
      if (ar.succeeded()) {
        callback(null, null);
      } else {
        callback(null, ar.cause());
      }
    });
      return that;
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   available on all providers.

   @public
   @param callback {function} - The callback function returning the results. 
   @return {AccessToken}
   */
  this.logout = function(callback) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'function') {
      j_accessToken["logout(io.vertx.core.Handler)"](function(ar) {
      if (ar.succeeded()) {
        callback(null, null);
      } else {
        callback(null, ar.cause());
      }
    });
      return that;
    } else throw new TypeError('function invoked with invalid arguments');
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_accessToken;
};

// We export the Constructor function
module.exports = AccessToken;