/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.impl.OAuth2API;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Auth extends AuthProvider {

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx) {
    return create(vertx, new OAuth2ClientOptions());
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx  the Vertx instance
   * @param config the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2ClientOptions config) {
    return new OAuth2AuthProviderImpl(new OAuth2API(vertx, config), config);
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   *
   * @param params extra parameters to apply to the url
   * @return future result
   * @see OAuth2Auth#decodeToken(String, Handler)
   */
  default Future<String> authorizeURL(JsonObject params) {
    Promise<String> promise = Promise.promise();
    authorizeURL(params, promise);
    return promise.future();
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   */
  @Fluent
  OAuth2Auth authorizeURL(JsonObject params, Handler<AsyncResult<String>> handler);

  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @param token   the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @param token the access token (base64 string)
   * @return future result
   * @see OAuth2Auth#decodeToken(String, Handler)
   */
  default Future<AccessToken> decodeToken(String token) {
    Promise<AccessToken> promise = Promise.promise();
    decodeToken(token, promise);
    return promise.future();
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token   the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  default OAuth2Auth introspectToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    return introspectToken(token, "access_token", handler);
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token the access token (base64 string)
   * @return future result
   * @see OAuth2Auth#introspectToken(String, Handler)
   */
  default Future<AccessToken> introspectToken(String token) {
    Promise<AccessToken> promise = Promise.promise();
    introspectToken(token, promise);
    return promise.future();
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token     the access token (base64 string)
   * @param tokenType hint to the token type e.g.: `access_token`
   * @param handler   A handler to receive the event
   * @return self
   */
  @Fluent
  OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Returns the configured flow type for the Oauth2 provider.
   *
   * @return the flow type.
   */
  OAuth2FlowType getFlowType();

  /**
   * Loads a JWK Set from the remote provider.
   * <p>
   * When calling this method several times, the loaded JWKs are updated in the underlying JWT object.
   */
  @Fluent
  OAuth2Auth loadJWK(Handler<AsyncResult<Void>> handler);

  /**
   * Loads a JWK Set from the remote provider.
   * <p>
   * When calling this method several times, the loaded JWKs are updated in the underlying JWT object.
   *
   * @see OAuth2Auth#loadJWK(Handler)
   */
  default Future<Void> loadJWK() {
    Promise<Void> promise = Promise.promise();
    loadJWK(promise);
    return promise.future();
  }

  /**
   * Generate a redirect URL to the authN/Z backend.
   *
   * @param params extra parameters to apply to the url
   * @return future result
   * @see OAuth2Auth#decodeToken(String, Handler)
   */
  default Future<String> endSessionURL(String idToken, JsonObject params) {
    Promise<String> promise = Promise.promise();
    endSessionURL(idToken, params, promise);
    return promise.future();
  }

  /**
   * Generate a redirect URL to the authN/Z backend.
   */
  @Fluent
  OAuth2Auth endSessionURL(String idToken, JsonObject params, Handler<AsyncResult<String>> handler);

  @Fluent
  OAuth2Auth rbacHandler(OAuth2RBAC rbac);
}
