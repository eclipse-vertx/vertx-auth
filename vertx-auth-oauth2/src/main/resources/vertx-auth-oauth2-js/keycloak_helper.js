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

/** @module vertx-auth-oauth2-js/keycloak_helper */
var utils = require('vertx-js/util/utils');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JKeycloakHelper = io.vertx.ext.auth.oauth2.KeycloakHelper;

/**
 Helper class for processing Keycloak principal.

 @class
 */
var KeycloakHelper = function (j_val) {

  var j_keycloakHelper = j_val;
  var that = this;

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_keycloakHelper;
};

/**
 Get raw `id_token` string from the principal.

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object} user principal
 @return {string} the raw id token string
 */
KeycloakHelper.getRawIdToken = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getRawIdToken(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**
 Get decoded `id_token` from the principal.

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object} user principal
 @return {Object} the id token
 */
KeycloakHelper.getIdToken = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return utils.convReturnJson(JKeycloakHelper["getIdToken(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal)));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**
 Get raw `access_token` string from the principal.

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object} user principal
 @return {string} the raw access token string
 */
KeycloakHelper.getRawAccessToken = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getRawAccessToken(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**
 Get decoded `access_token` from the principal.

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object} user principal
 @return {Object} the access token
 */
KeycloakHelper.getAccessToken = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return utils.convReturnJson(JKeycloakHelper["getAccessToken(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal)));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {number}
 */
KeycloakHelper.getAuthTime = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getAuthTime(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getSessionState = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getSessionState(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getAcr = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getAcr(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getName = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getName(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getEmail = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getEmail(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getPreferredUsername = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getPreferredUsername(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {string}
 */
KeycloakHelper.getNickName = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return JKeycloakHelper["getNickName(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param principal {Object}
 @return {Array.<string>}
 */
KeycloakHelper.getAllowedOrigins = function (principal) {
  var __args = arguments;
  if (__args.length === 1 && (typeof __args[0] === 'object' && __args[0] != null)) {
    return utils.convReturnSet(JKeycloakHelper["getAllowedOrigins(io.vertx.core.json.JsonObject)"](utils.convParamJsonObject(principal)));
  } else throw new TypeError('function invoked with invalid arguments');
};

/**
 Parse the token string with base64 encoder.
 This will only obtain the "payload" part of the token.

 @memberof module:vertx-auth-oauth2-js/keycloak_helper
 @param token {string} token string
 @return {Object} token payload json object
 */
KeycloakHelper.parseToken = function (token) {
  var __args = arguments;
  if (__args.length === 1 && typeof __args[0] === 'string') {
    return utils.convReturnJson(JKeycloakHelper["parseToken(java.lang.String)"](token));
  } else throw new TypeError('function invoked with invalid arguments');
};

// We export the Constructor function
module.exports = KeycloakHelper;