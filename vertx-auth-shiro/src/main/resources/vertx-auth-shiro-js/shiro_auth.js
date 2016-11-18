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

/** @module vertx-auth-shiro-js/shiro_auth */
var utils = require('vertx-js/util/utils');
var User = require('vertx-auth-common-js/user');
var Vertx = require('vertx-js/vertx');
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JShiroAuth = io.vertx.ext.auth.shiro.ShiroAuth;
var ShiroAuthOptions = io.vertx.ext.auth.shiro.ShiroAuthOptions;

/**

 @class
*/
var ShiroAuth = function(j_val) {

  var j_shiroAuth = j_val;
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
      j_shiroAuth["authenticate(io.vertx.core.json.JsonObject,io.vertx.core.Handler)"](utils.convParamJsonObject(arg0), function(ar) {
      if (ar.succeeded()) {
        arg1(utils.convReturnVertxGen(User, ar.result()), null);
      } else {
        arg1(null, ar.cause());
      }
    });
    } else throw new TypeError('function invoked with invalid arguments');
  };

  /**
   Set the role prefix to distinguish from permissions when checking for isPermitted requests.

   @public
   @param rolePrefix {string} a Prefix e.g.: "role:" 
   @return {ShiroAuth} a reference to this for fluency
   */
  this.setRolePrefix = function(rolePrefix) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(ShiroAuth, j_shiroAuth["setRolePrefix(java.lang.String)"](rolePrefix));
    } else throw new TypeError('function invoked with invalid arguments');
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_shiroAuth;
};

ShiroAuth._jclass = utils.getJavaClass("io.vertx.ext.auth.shiro.ShiroAuth");
ShiroAuth._jtype = {
  accept: function(obj) {
    return ShiroAuth._jclass.isInstance(obj._jdel);
  },
  wrap: function(jdel) {
    var obj = Object.create(ShiroAuth.prototype, {});
    ShiroAuth.apply(obj, arguments);
    return obj;
  },
  unwrap: function(obj) {
    return obj._jdel;
  }
};
ShiroAuth._create = function(jdel) {
  var obj = Object.create(ShiroAuth.prototype, {});
  ShiroAuth.apply(obj, arguments);
  return obj;
}
/**
 Create a Shiro auth provider

 @memberof module:vertx-auth-shiro-js/shiro_auth
 @param vertx {Vertx} the Vert.x instance 
 @param realmType {Object} the Shiro realm type 
 @param config {Object} the config 
 @return {ShiroAuth} the auth provider
 */
ShiroAuth.create = function() {
  var __args = arguments;
  if (__args.length === 2 && typeof __args[0] === 'object' && __args[0]._jdel && (typeof __args[1] === 'object' && __args[1] != null)) {
    return utils.convReturnVertxGen(ShiroAuth, JShiroAuth["create(io.vertx.core.Vertx,io.vertx.ext.auth.shiro.ShiroAuthOptions)"](__args[0]._jdel, __args[1] != null ? new ShiroAuthOptions(new JsonObject(JSON.stringify(__args[1]))) : null));
  }else if (__args.length === 3 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && (typeof __args[2] === 'object' && __args[2] != null)) {
    return utils.convReturnVertxGen(ShiroAuth, JShiroAuth["create(io.vertx.core.Vertx,io.vertx.ext.auth.shiro.ShiroAuthRealmType,io.vertx.core.json.JsonObject)"](__args[0]._jdel, io.vertx.ext.auth.shiro.ShiroAuthRealmType.valueOf(__args[1]), utils.convParamJsonObject(__args[2])));
  } else throw new TypeError('function invoked with invalid arguments');
};

module.exports = ShiroAuth;