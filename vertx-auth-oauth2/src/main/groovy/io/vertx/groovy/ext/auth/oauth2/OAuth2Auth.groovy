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
import io.vertx.core.http.HttpMethod
import io.vertx.groovy.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.core.AsyncResult
import io.vertx.ext.auth.oauth2.OAuth2FlowType
import io.vertx.core.Handler
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating OAuth2 based {@link io.vertx.groovy.ext.auth.AuthProvider} instances.
*/
@CompileStatic
public class OAuth2Auth extends AuthProvider {
  private final def io.vertx.ext.auth.oauth2.OAuth2Auth delegate;
  public OAuth2Auth(Object delegate) {
    super((io.vertx.ext.auth.oauth2.OAuth2Auth) delegate);
    this.delegate = (io.vertx.ext.auth.oauth2.OAuth2Auth) delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Create a OAuth2 auth provider
   * @param vertx the Vertx instance
   * @param flow 
   * @param config the config (see <a href="../../../../../../../../cheatsheet/OAuth2ClientOptions.html">OAuth2ClientOptions</a>)
   * @return the auth provider
   */
  public static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, Map<String, Object> config) {
    def ret= InternalHelper.safeCreate(io.vertx.ext.auth.oauth2.OAuth2Auth.create((io.vertx.core.Vertx)vertx.getDelegate(), flow, config != null ? new io.vertx.ext.auth.oauth2.OAuth2ClientOptions(new io.vertx.core.json.JsonObject(config)) : null), io.vertx.groovy.ext.auth.oauth2.OAuth2Auth.class);
    return ret;
  }
  /**
   * Create a OAuth2 auth provider
   * @param vertx the Vertx instance
   * @param flow 
   * @return the auth provider
   */
  public static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow) {
    def ret= InternalHelper.safeCreate(io.vertx.ext.auth.oauth2.OAuth2Auth.create((io.vertx.core.Vertx)vertx.getDelegate(), flow), io.vertx.groovy.ext.auth.oauth2.OAuth2Auth.class);
    return ret;
  }
  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   * @param params 
   * @return 
   */
  public String authorizeURL(Map<String, Object> params) {
    def ret = this.delegate.authorizeURL(params != null ? new io.vertx.core.json.JsonObject(params) : null);
    return ret;
  }
  /**
   * Returns the Access Token object.
   * @param params - JSON with the options, each flow requires different options.
   * @param handler - The handler returning the results.
   */
  public void getToken(Map<String, Object> params, Handler<AsyncResult<AccessToken>> handler) {
    this.delegate.getToken(params != null ? new io.vertx.core.json.JsonObject(params) : null, new Handler<AsyncResult<io.vertx.ext.auth.oauth2.AccessToken>>() {
      public void handle(AsyncResult<io.vertx.ext.auth.oauth2.AccessToken> event) {
        AsyncResult<AccessToken> f
        if (event.succeeded()) {
          f = InternalHelper.<AccessToken>result(new AccessToken(event.result()))
        } else {
          f = InternalHelper.<AccessToken>failure(event.cause())
        }
        handler.handle(f)
      }
    });
  }
  /**
   * Call OAuth2 APIs.
   * @param method HttpMethod
   * @param path target path
   * @param params parameters
   * @param handler handler
   * @return self
   */
  public OAuth2Auth api(HttpMethod method, String path, Map<String, Object> params, Handler<AsyncResult<Map<String, Object>>> handler) {
    this.delegate.api(method, path, params != null ? new io.vertx.core.json.JsonObject(params) : null, new Handler<AsyncResult<io.vertx.core.json.JsonObject>>() {
      public void handle(AsyncResult<io.vertx.core.json.JsonObject> event) {
        AsyncResult<Map<String, Object>> f
        if (event.succeeded()) {
          f = InternalHelper.<Map<String, Object>>result((Map<String, Object>)InternalHelper.wrapObject(event.result()))
        } else {
          f = InternalHelper.<Map<String, Object>>failure(event.cause())
        }
        handler.handle(f)
      }
    });
    return this;
  }
  /**
   * Returns true if this provider supports JWT tokens as the access_token. This is typically true if the provider
   * implements the `openid-connect` protocol. This is a plain return from the config option jwtToken, which is false
   * by default.
   *
   * This information is important to validate grants. Since pure OAuth2 should be used for authorization and when a
   * token is requested all grants should be declared, in case of openid-connect this is not true. OpenId will issue
   * a token and all grants will be encoded on the token itself so the requester does not need to list the required
   * grants.
   * @return true if openid-connect is used.
   */
  public boolean hasJWTToken() {
    def ret = this.delegate.hasJWTToken();
    return ret;
  }
}
