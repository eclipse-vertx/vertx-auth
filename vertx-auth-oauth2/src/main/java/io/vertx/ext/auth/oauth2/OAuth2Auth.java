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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.authentication.AuthenticationProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Auth extends AuthenticationProvider {

  /**
   * Create a OAuth2 auth provider.
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx) {
    return create(vertx, new OAuth2Options());
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2Options config) {
    return new OAuth2AuthProviderImpl(vertx, config);
  }

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity
   * of issued ID and access tokens. The provider will refresh the keys according to:
   * https://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys
   *
   * This means that the provider will look at the cache headers and will refresh when
   * the max-age is reached. If the server does not return any cache headers it shall
   * be up to the end user to call this method to refresh.
   *
   * To avoid the refresh to happen too late, this means that they keys will be invalid,
   * if the {@link OAuth2Options} {@link io.vertx.ext.auth.JWTOptions} config contains a
   * positive leeway, it will be used to request the refresh ahead of time.
   *
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  @Deprecated
  default OAuth2Auth jWKSet(Handler<AsyncResult<Void>> handler) {
    jWKSet()
      .onComplete(handler);

    return this;
  }

  /**
   * Retrieve the public server JSON Web Key (JWK) required to verify the authenticity
   * of issued ID and access tokens.

   * @return Future result.
   * @see OAuth2Auth#jWKSet(Handler)
   */
  Future<Void> jWKSet();

  /**
   * Handled to be called when a key (mentioned on a JWT) is missing from the current config.
   * Users are advised to call {@link OAuth2Auth#jWKSet(Handler)} but being careful to implement
   * some rate limiting function.
   *
   * This method isn't generic for several reasons. The provider is not aware of the capabilities
   * of the backend IdP in terms of max allowed API calls. Some validation could be done at the
   * key id, which only the end user is aware of.
   *
   * A base implementation for this handler is:
   *
   * <pre>{@code
   *   // are we already updating the jwks?
   *   private final AtomicBoolean updating = new AtomicBoolean(false);
   *
   *   // default missing key handler, will try to reload with debounce
   *   oauth2.missingKeyHandler(keyId -> {
   *     if (updating.compareAndSet(false, true)) {
   *       // Refreshing JWKs due missing key
   *       jWKSet(done -> {
   *         updating.compareAndSet(true, false);
   *         if (done.failed()) {
   *           done.cause().printStackTrace();
   *         }
   *       });
   *     }
   *   });
   * }</pre>
   *
   * This handler will purely debounce calls and allow only a single request to {@link #jWKSet()}
   * at a time. No special handling is done to avoid requests on wrong key ids or prevent to many
   * requests to the IdP server. Users should probably also account for the number of errors to
   * present DDoS the IdP.
   *
   * @return Future result.
   * @see OAuth2Auth#missingKeyHandler(Handler)
   */
  @Fluent
  OAuth2Auth missingKeyHandler(Handler<String> handler);

  /**
   * The client sends the end-user's browser to this endpoint to request their
   * authentication and consent. This endpoint is used in the code and implicit
   * OAuth 2.0 flows which require end-user interaction.
   *
   * @param url Base URL with path together with other parameters to be included in the final URL.
   * @return the url to be used to authorize the user.
   */
  String authorizeURL(OAuth2AuthorizationURL url);

  /**
   * Refresh the current User (access token).
   *
   * @param user the user (access token) to be refreshed.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  @Deprecated
  default OAuth2Auth refresh(User user, Handler<AsyncResult<User>> handler) {
    refresh(user)
      .onComplete(handler);

    return this;
  }

  /**
   * Refresh the current User (access token).
   *
   * @param user the user (access token) to be refreshed.
   * @return future result
   * @see OAuth2Auth#userInfo(User, Handler)
   */
  Future<User> refresh(User user);

  /**
   * Revoke an obtained access or refresh token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param tokenType the token type (either access_token or refresh_token).
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  @Deprecated
  default OAuth2Auth revoke(User user, String tokenType, Handler<AsyncResult<Void>> handler) {
    revoke(user, tokenType)
      .onComplete(handler);

    return this;
  }

  /**
   * Revoke an obtained access token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  @Deprecated
  default OAuth2Auth revoke(User user, Handler<AsyncResult<Void>> handler) {
    revoke(user, "access_token")
      .onComplete(handler);

    return this;
  }

  /**
   * Revoke an obtained access or refresh token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @param tokenType the token type (either access_token or refresh_token).
   * @return future result
   * @see OAuth2Auth#revoke(User, String, Handler)
   */
  Future<Void> revoke(User user, String tokenType);

  /**
   * Revoke an obtained access token. More info <a href="https://tools.ietf.org/html/rfc7009">https://tools.ietf.org/html/rfc7009</a>.
   *
   * @param user the user (access token) to revoke.
   * @return future result
   * @see OAuth2Auth#revoke(User, Handler)
   */
  default Future<Void> revoke(User user) {
    return revoke(user, "access_token");
  }

  /**
   * Retrieve profile information and other attributes for a logged-in end-user. More info <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
   *
   * @param user the user (access token) to fetch the user info.
   * @param handler the handler success/failure.
   * @return fluent self.
   */
  @Fluent
  @Deprecated
  default OAuth2Auth userInfo(User user, Handler<AsyncResult<JsonObject>> handler) {
    userInfo(user)
      .onComplete(handler);

    return this;
  }

  /**
   * Retrieve profile information and other attributes for a logged-in end-user. More info <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">https://openid.net/specs/openid-connect-core-1_0.html#UserInfo</a>
   *
   * @param user the user (access token) to fetch the user info.
   * @return future result
   * @see OAuth2Auth#userInfo(User, Handler)
   */
  Future<JsonObject> userInfo(User user);

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
   * Releases any resources or timers used by this instance. Users are expected to call this method when the provider
   * isn't needed any more to return the used resources back to the platform.
   */
  void close();
}
