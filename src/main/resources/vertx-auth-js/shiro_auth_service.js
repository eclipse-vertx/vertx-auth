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

/** @module vertx-auth-js/shiro_auth_service */
var utils = require('vertx-js/util/utils');
var AuthService = require('vertx-auth-js/auth_service');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JShiroAuthService = io.vertx.ext.auth.shiro.ShiroAuthService;

/**
 An Auth service implementation that uses Apache Shiro internally.
 <p>

 @class
*/
var ShiroAuthService = function(j_val) {

  var j_shiroAuthService = j_val;
  var that = this;
  AuthService.call(this, j_val);

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_shiroAuthService;
};

/**
 Create an auth service using the specified auth realm type.

 @memberof module:vertx-auth-js/shiro_auth_service
 @param vertx {Vertx} the Vert.x intance 
 @param authRealmType {Object} the auth realm type 
 @param config {Object} the config to pass to the provider 
 @return {AuthService} the auth service
 */
ShiroAuthService.create = function(vertx, authRealmType, config) {
  var __args = arguments;
  if (__args.length === 3 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && typeof __args[2] === 'object') {
    return new AuthService(JShiroAuthService["create(io.vertx.core.Vertx,io.vertx.ext.auth.shiro.ShiroAuthRealmType,io.vertx.core.json.JsonObject)"](vertx._jdel, io.vertx.ext.auth.shiro.ShiroAuthRealmType.valueOf(__args[1]), utils.convParamJsonObject(config)));
  } else utils.invalidArgs();
};

// We export the Constructor function
module.exports = ShiroAuthService;