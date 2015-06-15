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
var AuthProvider = require('vertx-auth-common-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JShiroAuth = io.vertx.ext.auth.shiro.ShiroAuth;

/**

 @class
*/
var ShiroAuth = function(j_val) {

  var j_shiroAuth = j_val;
  var that = this;
  AuthProvider.call(this, j_val);

  /**
   Set the role prefix to distinguish from permissions when checking for isPermitted requests.

   @public
   @param rolePrefix {string} a Prefix e.g.: "role:" 
   @return {ShiroAuth} a reference to this for fluency
   */
  this.setRolePrefix = function(rolePrefix) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      return utils.convReturnVertxGen(j_shiroAuth["setRolePrefix(java.lang.String)"](rolePrefix), ShiroAuth);
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_shiroAuth;
};

/**
 Create a Shiro auth provider

 @memberof module:vertx-auth-shiro-js/shiro_auth
 @param vertx {Vertx} the Vert.x instance 
 @param realmType {Object} the Shiro realm type 
 @param config {Object} the config 
 @return {ShiroAuth} the auth provider
 */
ShiroAuth.create = function(vertx, realmType, config) {
  var __args = arguments;
  if (__args.length === 3 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && typeof __args[2] === 'object') {
    return utils.convReturnVertxGen(JShiroAuth["create(io.vertx.core.Vertx,io.vertx.ext.auth.shiro.ShiroAuthRealmType,io.vertx.core.json.JsonObject)"](vertx._jdel, io.vertx.ext.auth.shiro.ShiroAuthRealmType.valueOf(__args[1]), utils.convParamJsonObject(config)), ShiroAuth);
  } else utils.invalidArgs();
};

// We export the Constructor function
module.exports = ShiroAuth;