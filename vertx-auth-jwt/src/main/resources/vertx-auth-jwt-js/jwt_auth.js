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
var User = require('vertx-auth-common-js/user');
var Vertx = require('vertx-js/vertx');
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JJWTAuth = Java.type('io.vertx.ext.auth.jwt.JWTAuth');
var JWTOptions = Java.type('io.vertx.ext.auth.jwt.JWTOptions');

/**

 @class
*/
var JWTAuth = function(j_val) {

  var j_jWTAuth = j_val;
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
      j_jWTAuth["authenticate(io.vertx.core.json.JsonObject,io.vertx.core.Handler)"](utils.convParamJsonObject(arg0), function(ar) {
      if (ar.succeeded()) {
        arg1(utils.convReturnVertxGen(User, ar.result()), null);
      } else {
        arg1(null, ar.cause());
      }
    });
    } else throw new TypeError('function invoked with invalid arguments');
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
    if (__args.length === 2 && (typeof __args[0] === 'object' && __args[0] != null) && (typeof __args[1] === 'object' && __args[1] != null)) {
      return j_jWTAuth["generateToken(io.vertx.core.json.JsonObject,io.vertx.ext.auth.jwt.JWTOptions)"](utils.convParamJsonObject(claims), options != null ? new JWTOptions(new JsonObject(Java.asJSONCompatible(options))) : null);
    } else throw new TypeError('function invoked with invalid arguments');
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_jWTAuth;
};

JWTAuth._jclass = utils.getJavaClass("io.vertx.ext.auth.jwt.JWTAuth");
JWTAuth._jtype = {
  accept: function(obj) {
    return JWTAuth._jclass.isInstance(obj._jdel);
  },
  wrap: function(jdel) {
    var obj = Object.create(JWTAuth.prototype, {});
    JWTAuth.apply(obj, arguments);
    return obj;
  },
  unwrap: function(obj) {
    return obj._jdel;
  }
};
JWTAuth._create = function(jdel) {
  var obj = Object.create(JWTAuth.prototype, {});
  JWTAuth.apply(obj, arguments);
  return obj;
}
/**
 Create a JWT auth provider

 @memberof module:vertx-auth-jwt-js/jwt_auth
 @param vertx {Vertx} the Vertx instance 
 @param config {Object} the config 
 @return {JWTAuth} the auth provider
 */
JWTAuth.create = function(vertx, config) {
  var __args = arguments;
  if (__args.length === 2 && typeof __args[0] === 'object' && __args[0]._jdel && (typeof __args[1] === 'object' && __args[1] != null)) {
    return utils.convReturnVertxGen(JWTAuth, JJWTAuth["create(io.vertx.core.Vertx,io.vertx.core.json.JsonObject)"](vertx._jdel, utils.convParamJsonObject(config)));
  } else throw new TypeError('function invoked with invalid arguments');
};

module.exports = JWTAuth;