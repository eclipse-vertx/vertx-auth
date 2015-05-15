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

/** @module vertx-auth-js/clusterable_auth_provider */
var utils = require('vertx-js/util/utils');
var User = require('vertx-auth-js/user');
var Buffer = require('vertx-js/buffer');
var AuthProvider = require('vertx-auth-js/auth_provider');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JClusterableAuthProvider = io.vertx.ext.auth.ClusterableAuthProvider;

/**

 @class
*/
var ClusterableAuthProvider = function(j_val) {

  var j_clusterableAuthProvider = j_val;
  var that = this;
  AuthProvider.call(this, j_val);

  /**

   @public
   @param user {User} 
   @return {Buffer}
   */
  this.toBuffer = function(user) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      return new Buffer(j_clusterableAuthProvider["toBuffer(io.vertx.ext.auth.User)"](user._jdel));
    } else utils.invalidArgs();
  };

  /**

   @public
   @param buffer {Buffer} 
   @return {User}
   */
  this.fromBuffer = function(buffer) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      return new User(j_clusterableAuthProvider["fromBuffer(io.vertx.core.buffer.Buffer)"](buffer._jdel));
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_clusterableAuthProvider;
};

// We export the Constructor function
module.exports = ClusterableAuthProvider;