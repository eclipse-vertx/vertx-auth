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

/** @module vertx-auth-mongo-js/hash_strategy */
var utils = require('vertx-js/util/utils');
var User = require('vertx-auth-common-js/user');

var io = Packages.io;
var JsonObject = io.vertx.core.json.JsonObject;
var JHashStrategy = io.vertx.ext.auth.mongo.HashStrategy;

/**
 Determines how the hashing is computed in the implementation You can implement this to provide a different hashing
 strategy to the default.

 @class
*/
var HashStrategy = function(j_val) {

  var j_hashStrategy = j_val;
  var that = this;

  /**
   Compute the hashed password given the unhashed password and the user

   @public
   @param password {string} the unhashed password 
   @param user {User} the user to get the salt for. This paramter is needed, if the  is declared to be used 
   @return {string} the hashed password
   */
  this.computeHash = function(password, user) {
    var __args = arguments;
    if (__args.length === 2 && typeof __args[0] === 'string' && typeof __args[1] === 'object' && __args[1]._jdel) {
      return j_hashStrategy["computeHash(java.lang.String,io.vertx.ext.auth.User)"](password, user._jdel);
    } else utils.invalidArgs();
  };

  /**
   Retrieve the password from the user, or as clear text or as hashed version, depending on the definition

   @public
   @param user {User} the user to get the stored password for 
   @return {string} the password, either as hashed version or as cleartext, depending on the preferences
   */
  this.getStoredPwd = function(user) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      return j_hashStrategy["getStoredPwd(io.vertx.ext.auth.User)"](user._jdel);
    } else utils.invalidArgs();
  };

  /**
   Retrieve the salt. The source of the salt can be the external salt or the propriate column of the given user,
   depending on the defined HashSaltStyle

   @public
   @param user {User} the user to get the salt for. This paramter is needed, if the  is declared to be used 
   @return {string} null in case of  the salt of the user or a defined external salt
   */
  this.getSalt = function(user) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'object' && __args[0]._jdel) {
      return j_hashStrategy["getSalt(io.vertx.ext.auth.User)"](user._jdel);
    } else utils.invalidArgs();
  };

  /**
   Set an external salt. This method should be used in case of 

   @public
   @param salt {string} the salt, which shall be used 
   */
  this.setExternalSalt = function(salt) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      j_hashStrategy["setExternalSalt(java.lang.String)"](salt);
    } else utils.invalidArgs();
  };

  /**
   Set the saltstyle as defined by HashSaltStyle.

   @public
   @param saltStyle {Object} the HashSaltStyle to be used 
   */
  this.setSaltStyle = function(saltStyle) {
    var __args = arguments;
    if (__args.length === 1 && typeof __args[0] === 'string') {
      j_hashStrategy["setSaltStyle(io.vertx.ext.auth.mongo.HashSaltStyle)"](io.vertx.ext.auth.mongo.HashSaltStyle.valueOf(__args[0]));
    } else utils.invalidArgs();
  };

  /**
   Get the defined HashSaltStyle of the current instance

   @public

   @return {Object} the saltStyle
   */
  this.getSaltStyle = function() {
    var __args = arguments;
    if (__args.length === 0) {
      return (j_hashStrategy["getSaltStyle()"]()).toString();
    } else utils.invalidArgs();
  };

  // A reference to the underlying Java delegate
  // NOTE! This is an internal API and must not be used in user code.
  // If you rely on this property your code is likely to break if we change it / remove it without warning.
  this._jdel = j_hashStrategy;
};

// We export the Constructor function
module.exports = HashStrategy;