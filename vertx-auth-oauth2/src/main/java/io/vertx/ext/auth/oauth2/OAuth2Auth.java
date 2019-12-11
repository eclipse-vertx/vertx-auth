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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.impl.OAuth2API;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.authentication.AuthenticationProvider} instances.
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
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2ClientOptions config) {
    return new OAuth2AuthProviderImpl(new OAuth2API(vertx, config), config);
  }

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity
   * of issued ID and access tokens.
   *
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  OAuth2Auth jWKSet(Handler<AsyncResult<Void>> handler);

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity
   * of issued ID and access tokens.

   * @return Future result.
   * @see OAuth2Auth#jWKSet(Handler)
   */
  default Future<Void> jWKSet() {
    Promise<Void> promise = Promise.promise();
    jWKSet(promise);
    return promise.future();
  }

  /**
   * The client sends the end-user's browser to this endpoint to request their
   * authentication and consent. This endpoint is used in the code and implicit
   * OAuth 2.0 flows which require end-user interaction.
   *
   * @param params extra params to be included in the final URL.
   * @return the url to be used to authorize the user.
   */
  String authorizeURL(JsonObject params);

  /**
   * Refresh the current User (access token).
   *
   * @param user the user (access token) to be refreshed.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  OAuth2Auth refresh(User user, Handler<AsyncResult<User>> handler);

  /**
   * Refresh the current User (access token).
   *
   * @param user the user (access token) to be refreshed.
   * @return future result
   * @see OAuth2Auth#userInfo(User, Handler)
   */
  default Future<User> refresh(User user) {
    Promise<User> promise = Promise.promise();
    refresh(user, promise);
    return promise.future();
  }

  /**
   * Revoke an obtained access or refresh token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param tokenType the token type (either access_token or refresh_token).
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  OAuth2Auth revoke(User user, String tokenType, Handler<AsyncResult<Void>> handler);

  /**
   * Revoke an obtained access token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  default OAuth2Auth revoke(User user, Handler<AsyncResult<Void>> handler) {
    return revoke(user, "access_token", handler);
  }

  /**
   * Revoke an obtained access or refresh token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param tokenType the token type (either access_token or refresh_token).
   * @return future result
   * @see OAuth2Auth#revoke(User, String, Handler)
   */
  default Future<Void> revoke(User user, String tokenType) {
    Promise<Void> promise = Promise.promise();
    revoke(user, tokenType, promise);
    return promise.future();
  }

  /**
   * Revoke an obtained access token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @return future result
   * @see OAuth2Auth#revoke(User, Handler)
   */
  default Future<Void> revoke(User user) {
    Promise<Void> promise = Promise.promise();
    revoke(user, promise);
    return promise.future();
  }

  /**
   * Retrieve profile information and other attributes for a logged-in end-user. More info <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
   *
   * @param user the user (access token) to fetch the user info.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  OAuth2Auth userInfo(User user, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Retrieve profile information and other attributes for a logged-in end-user. More info <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
   *
   * @param user the user (access token) to fetch the user info.
   * @return future result
   * @see OAuth2Auth#userInfo(User, Handler)
   */
  default Future<JsonObject> userInfo(User user) {
    Promise<JsonObject> promise = Promise.promise();
    userInfo(user, promise);
    return promise.future();
  }

  /**
   * The logout (end-session) endpoint is specified in OpenID Connect Session Management 1.0.
   * More info: <a href="https://openid.net/specs/openid-connect-session-1_0.html">https://openid.net/specs/openid-connect-session-1_0.html</a>.
   *
   * @param user the user to generate the url for
   * @param params extra parameters to apply to the url
   * @return the url to end the session.
   */
  String endSessionURL(User user, JsonObject params);

  /**
   * The logout (end-session) endpoint is specified in OpenID Connect Session Management 1.0.
   * More info: <a href="https://openid.net/specs/openid-connect-session-1_0.html">https://openid.net/specs/openid-connect-session-1_0.html</a>.
   *
   * @param user the user to generate the url for
   * @return the url to end the session.
   */
  default String endSessionURL(User user) {
    return endSessionURL(user, new JsonObject());
  }

  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @param token the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  @Deprecated
  OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @see OAuth2Auth#decodeToken(String, Handler)
   * @param token the access token (base64 string)
   * @return future result
   */
  @Deprecated
  default Future<AccessToken> decodeToken(String token) {
    Promise<AccessToken> promise = Promise.promise();
    decodeToken(token, promise);
    return promise.future();
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  @Deprecated
  default OAuth2Auth introspectToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    return introspectToken(token, "access_token", handler);
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @see OAuth2Auth#introspectToken(String, Handler)
   * @param token the access token (base64 string)
   * @return future result
   */
  @Deprecated
  default Future<AccessToken> introspectToken(String token) {
    Promise<AccessToken> promise = Promise.promise();
    introspectToken(token, promise);
    return promise.future();
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token the access token (base64 string)
   * @param tokenType hint to the token type e.g.: `access_token`
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  @Deprecated
  OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Returns the configured flow type for the Oauth2 provider.
   *
   * @return the flow type.
   */
  @Deprecated
  OAuth2FlowType getFlowType();

  /**
   * Loads a JWK Set from the remote provider.
   *
   * When calling this method several times, the loaded JWKs are updated in the underlying JWT object.
   * @deprecated Use {@link #jWKSet(Handler)}
   */
  @Fluent
  @Deprecated
  default OAuth2Auth loadJWK(Handler<AsyncResult<Void>> handler) {
    return jWKSet(handler);
  }

  /**
   * Loads a JWK Set from the remote provider.
   *
   * When calling this method several times, the loaded JWKs are updated in the underlying JWT object.
   * @see OAuth2Auth#loadJWK(Handler)
   * @deprecated Use {@link #jWKSet()}
   */
  @Deprecated
  default Future<Void> loadJWK() {
    Promise<Void> promise = Promise.promise();
    loadJWK(promise);
    return promise.future();
  }

  @Fluent
  @Deprecated
  OAuth2Auth rbacHandler(OAuth2RBAC rbac);
}
