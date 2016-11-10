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

package io.vertx.groovy.ext.auth.oauth2;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.core.json.JsonObject
import io.vertx.groovy.ext.auth.User
import io.vertx.core.json.JsonObject
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * AccessToken extension to the User interface
*/
@CompileStatic
public class AccessToken extends User {
  private final def io.vertx.ext.auth.oauth2.AccessToken delegate;
  public AccessToken(Object delegate) {
    super((io.vertx.ext.auth.oauth2.AccessToken) delegate);
    this.delegate = (io.vertx.ext.auth.oauth2.AccessToken) delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Check if the access token is expired or not.
   * @return 
   */
  public boolean expired() {
    def ret = delegate.expired();
    return ret;
  }
  /**
   * Refresh the access token
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken refresh(Handler<AsyncResult<Void>> callback) {
    delegate.refresh(callback);
    return this;
  }
  /**
   * Revoke access or refresh token
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken revoke(String token_type, Handler<AsyncResult<Void>> callback) {
    delegate.revoke(token_type, callback);
    return this;
  }
  /**
   * Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   * available on all providers.
   * @param callback - The callback function returning the results.
   * @return 
   */
  public AccessToken logout(Handler<AsyncResult<Void>> callback) {
    delegate.logout(callback);
    return this;
  }
}
