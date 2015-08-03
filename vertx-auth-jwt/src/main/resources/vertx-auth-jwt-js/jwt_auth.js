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

/** @module vertx-auth-jwt-js/jwt_auth */
var utils = require('vertx-js/util/utils');
var Vertx = require('vertx-js/vertx');
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JJWTAuth = io.vertx.ext.auth.jwt.JWTAuth;
var JksOptions = io.vertx.core.net.JksOptions;
var JWTOptions = io.vertx.ext.auth.jwt.JWTOptions;

/**

 @class
*/
var JWTAuth = function(j_val) {

  var j_jWTAuth = j_val;
  var that = this;
  AuthProvider.call(this, j_val);

  /**
   Sets the key name in the json token where permission claims will be listed.

   @public
   @param name {string} the key name 
   @return {JWTAuth} self
   */
  this.setPermissionsClaimKey = function(name) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      j_jWTAuth["setPermissionsClaimKey(java.lang.String)"](name);
      return that;
    } else utils.invalidArgs();
  };

  /**
   Generate a new JWT token.

   @public
   @param claims {Object} Json with user defined claims for a list of official claims 
   @param options {Object} extra options for the generation 
   @return {string} JWT encoded token
   */
  this.generateToken = function(claims, options) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'object' && typeof __args[1] === 'object') {
      return j_jWTAuth["generateToken(io.vertx.core.json.JsonObject,io.vertx.ext.auth.jwt.JWTOptions)"](utils.convParamJsonObject(claims), options != null ? new JWTOptions(new JsonObject(JSON.stringify(options))) : null);
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_jWTAuth;
};

/**
 Create a JWT auth provider

 @memberof module:vertx-auth-jwt-js/jwt_auth
 @param vertx {Vertx} the Vertx instance 
 @param config {Object} the config 
 @return {JWTAuth} the auth provider
 */
JWTAuth.create = function() {
  var __args = arguments;
  if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
    return utils.convReturnVertxGen(JJWTAuth["create(io.vertx.core.Vertx)"](__args[0]._jdel), JWTAuth);
  }else if (__args.length === 2 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'object') {
    return utils.convReturnVertxGen(JJWTAuth["create(io.vertx.core.Vertx,io.vertx.core.net.JksOptions)"](__args[0]._jdel, __args[1] != null ? new JksOptions(new JsonObject(JSON.stringify(__args[1]))) : null), JWTAuth);
  } else utils.invalidArgs();
};

// We export the Constructor function
module.exports = JWTAuth;