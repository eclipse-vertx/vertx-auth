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

package io.vertx.rxjava.ext.auth.oauth2;

import java.util.Map;
import rx.Observable;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.core.Handler;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.rxjava.ext.auth.AuthProvider;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.rxjava.ext.auth.AuthProvider} instances.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.OAuth2Auth original} non RX-ified interface using Vert.x codegen.
 */

public class OAuth2Auth extends AuthProvider {

  final io.vertx.ext.auth.oauth2.OAuth2Auth delegate;

  public OAuth2Auth(io.vertx.ext.auth.oauth2.OAuth2Auth delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Create a OAuth2 auth provider
   * @param vertx the Vertx instance
   * @param flow 
   * @param config the config as exported from the admin console
   * @return the auth provider
   */
  public static OAuth2Auth createKeycloak(Vertx vertx, OAuth2FlowType flow, JsonObject config) { 
    OAuth2Auth ret = OAuth2Auth.newInstance(io.vertx.ext.auth.oauth2.OAuth2Auth.createKeycloak((io.vertx.core.Vertx)vertx.getDelegate(), flow, config));
    return ret;
  }

  /**
   * Create a OAuth2 auth provider
   * @param vertx the Vertx instance
   * @param flow 
   * @param config the config
   * @return the auth provider
   */
  public static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) { 
    OAuth2Auth ret = OAuth2Auth.newInstance(io.vertx.ext.auth.oauth2.OAuth2Auth.create((io.vertx.core.Vertx)vertx.getDelegate(), flow, config));
    return ret;
  }

  /**
   * Create a OAuth2 auth provider
   * @param vertx the Vertx instance
   * @param flow 
   * @return the auth provider
   */
  public static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow) { 
    OAuth2Auth ret = OAuth2Auth.newInstance(io.vertx.ext.auth.oauth2.OAuth2Auth.create((io.vertx.core.Vertx)vertx.getDelegate(), flow));
    return ret;
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   * @param params 
   * @return 
   */
  public String authorizeURL(JsonObject params) { 
    String ret = delegate.authorizeURL(params);
    return ret;
  }

  /**
   * Returns the Access Token object.
   * @param params - JSON with the options, each flow requires different options.
   * @param handler - The handler returning the results.
   */
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler) { 
    delegate.getToken(params, new Handler<AsyncResult<io.vertx.ext.auth.oauth2.AccessToken>>() {
      public void handle(AsyncResult<io.vertx.ext.auth.oauth2.AccessToken> ar) {
        if (ar.succeeded()) {
          handler.handle(io.vertx.core.Future.succeededFuture(AccessToken.newInstance(ar.result())));
        } else {
          handler.handle(io.vertx.core.Future.failedFuture(ar.cause()));
        }
      }
    });
  }

  /**
   * Returns the Access Token object.
   * @param params - JSON with the options, each flow requires different options.
   * @return 
   */
  public Observable<AccessToken> getTokenObservable(JsonObject params) { 
    io.vertx.rx.java.ObservableFuture<AccessToken> handler = io.vertx.rx.java.RxHelper.observableFuture();
    getToken(params, handler.toHandler());
    return handler;
  }

  /**
   * Call OAuth2 APIs.
   * @param method HttpMethod
   * @param path target path
   * @param params parameters
   * @param handler handler
   * @return self
   */
  public OAuth2Auth api(HttpMethod method, String path, JsonObject params, Handler<AsyncResult<JsonObject>> handler) { 
    delegate.api(method, path, params, handler);
    return this;
  }

  /**
   * Call OAuth2 APIs.
   * @param method HttpMethod
   * @param path target path
   * @param params parameters
   * @return 
   */
  public Observable<JsonObject> apiObservable(HttpMethod method, String path, JsonObject params) { 
    io.vertx.rx.java.ObservableFuture<JsonObject> handler = io.vertx.rx.java.RxHelper.observableFuture();
    api(method, path, params, handler.toHandler());
    return handler;
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
    boolean ret = delegate.hasJWTToken();
    return ret;
  }


  public static OAuth2Auth newInstance(io.vertx.ext.auth.oauth2.OAuth2Auth arg) {
    return arg != null ? new OAuth2Auth(arg) : null;
  }
}
