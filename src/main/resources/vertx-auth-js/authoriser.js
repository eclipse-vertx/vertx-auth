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

/** @module vertx-auth-js/authoriser */
var utils = require('vertx-js/util/utils');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JAuthoriser = io.vertx.ext.auth.Authoriser;

/**

 @class
*/
var Authoriser = function(j_val) {

  var j_authoriser = j_val;
  var that = this;

  /**

   @public
   @param principal {Object} 
   @param role {string} 
   @param resultHandler {function} 
   */
  this.hasRole = function(principal, role, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authoriser["hasRole(io.vertx.core.json.JsonObject,java.lang.String,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), role, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  /**

   @public
   @param principal {Object} 
   @param permission {string} 
   @param resultHandler {function} 
   */
  this.hasPermission = function(principal, permission, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'string' && typeof __args[2] === 'function') {
      j_authoriser["hasPermission(io.vertx.core.json.JsonObject,java.lang.String,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), permission, function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  /**

   @public
   @param principal {Object} 
   @param roles {Array.<string>} 
   @param resultHandler {function} 
   */
  this.hasRoles = function(principal, roles, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'object' && __args[1] instanceof Array && typeof __args[2] === 'function') {
      j_authoriser["hasRoles(io.vertx.core.json.JsonObject,java.util.Set,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), utils.convParamSetBasicOther(roles), function(ar) {
      if (ar.succeeded()) {
        resultHandler(ar.result(), null);
      } else {
        resultHandler(null, ar.cause());
      }
    });
    } else utils.invalidArgs();
  };

  /**

   @public
   @param principal {Object} 
   @param permissions {Array.<string>} 
   @param resultHandler {function} 
   */
  this.hasPermissions = function(principal, permissions, resultHandler) {
    var __args = arguments;
    if (__args.length === 3 && typeof __args[0] === 'object' && typeof __args[1] === 'object' && __args[1] instanceof Array && typeof __args[2] === 'function') {
      j_authoriser["hasPermissions(io.vertx.core.json.JsonObject,java.util.Set,io.vertx.core.Handler)"](utils.convParamJsonObject(principal), utils.convParamSetBasicOther(permissions), function(ar) {
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
  this._jdel = j_authoriser;
};

// We export the Constructor function
module.exports = Authoriser;