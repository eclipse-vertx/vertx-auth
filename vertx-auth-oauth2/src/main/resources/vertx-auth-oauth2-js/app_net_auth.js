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

/** @module vertx-auth-oauth2-js/app_net_auth */
var utils = require('vertx-js/util/utils');
var Vertx = require('vertx-js/vertx');
var OAuth2Auth = require('vertx-auth-oauth2-js/o_auth2_auth');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JAppNetAuth = io.vertx.ext.auth.oauth2.providers.AppNetAuth;
var HttpClientOptions = io.vertx.core.http.HttpClientOptions;

/**

 @class
*/
var AppNetAuth = function(j_val) {

  var j_appNetAuth = j_val;
  var that = this;

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_appNetAuth;
};

AppNetAuth._jclass = utils.getJavaClass("io.vertx.ext.auth.oauth2.providers.AppNetAuth");
AppNetAuth._jtype = {
  accept: function(obj) {
    return AppNetAuth._jclass.isInstance(obj._jdel);
  },
  wrap: function(jdel) {
    var obj = Object.create(AppNetAuth.prototype, {});
    AppNetAuth.apply(obj, arguments);
    return obj;
  },
  unwrap: function(obj) {
    return obj._jdel;
  }
};
AppNetAuth._create = function(jdel) {
  var obj = Object.create(AppNetAuth.prototype, {});
  AppNetAuth.apply(obj, arguments);
  return obj;
}
/**
 Create a OAuth2Auth provider for App.net

 @memberof module:vertx-auth-oauth2-js/app_net_auth
 @param vertx {Vertx} 
 @param clientId {string} the client id given to you by App.net 
 @param clientSecret {string} the client secret given to you by App.net 
 @param httpClientOptions {Object} custom http client options 
 @return {OAuth2Auth}
 */
AppNetAuth.create = function() {
  var __args = arguments;
  if (__args.length === 3 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && typeof __args[2] === 'string') {
    return utils.convReturnVertxGen(OAuth2Auth, JAppNetAuth["create(io.vertx.core.Vertx,java.lang.String,java.lang.String)"](__args[0]._jdel, __args[1], __args[2]));
  }else if (__args.length === 4 && typeof __args[0] === 'object' && __args[0]._jdel && typeof __args[1] === 'string' && typeof __args[2] === 'string' && (typeof __args[3] === 'object' && __args[3] != null)) {
    return utils.convReturnVertxGen(OAuth2Auth, JAppNetAuth["create(io.vertx.core.Vertx,java.lang.String,java.lang.String,io.vertx.core.http.HttpClientOptions)"](__args[0]._jdel, __args[1], __args[2], __args[3] != null ? new HttpClientOptions(new JsonObject(JSON.stringify(__args[3]))) : null));
  } else throw new TypeError('function invoked with invalid arguments');
};

module.exports = AppNetAuth;