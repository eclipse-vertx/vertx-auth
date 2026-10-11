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
package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Twitch.
 * <p>
 * Twitch is an OpenID Connect provider, the endpoints are documented at
 * <a href="https://dev.twitch.tv/docs/authentication/">https://dev.twitch.tv/docs/authentication/</a> and
 * published in the discovery document {@code https://id.twitch.tv/oauth2/.well-known/openid-configuration}.
 * <p>
 * The {@code /userinfo} endpoint (requires the {@code openid} scope, see
 * <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/">https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/</a>)
 * always returns {@code aud}, {@code exp}, {@code iat}, {@code iss} and {@code sub} (the user id); the claims
 * {@code email}, {@code email_verified}, {@code picture}, {@code preferred_username} and {@code updated_at} are
 * only returned when requested with the {@code claims} parameter of the authorization request.
 * <p>
 * Twitch expects the client credentials in the body of the token request rather than in an HTTP Basic
 * {@code Authorization} header
 * (<a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/">https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/</a>),
 * the provider is configured accordingly.
 */
@VertxGen
public interface TwitchAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Twitch
   *
   * @param clientId     the client id given to you by Twitch
   * @param clientSecret the client secret given to you by Twitch
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Twitch
   *
   * @param clientId          the client id given to you by Twitch
   * @param clientSecret      the client secret given to you by Twitch
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        // issuer, https://id.twitch.tv/oauth2/.well-known/openid-configuration
        .setSite("https://id.twitch.tv/oauth2")
        .setAuthorizationPath("/authorize")
        .setTokenPath("/token")
        .setUserInfoPath("/userinfo")
        // https://dev.twitch.tv/docs/authentication/revoke-tokens/
        .setRevocationPath("/revoke")
        // RFC 7517
        .setJwkPath("/keys")
        .setScopeSeparator(" ")
        // client credentials must be sent in the request body
        .setUseBasicAuthorization(false));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx  the vertx instance
   * @param config the initial config
   * @return future with instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    // don't override if already set
    final String site = config.getSite() == null ? "https://id.twitch.tv/oauth2" : config.getSite();

    return OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options(config)
        .setSite(site)
        // client credentials must be sent in the request body
        .setUseBasicAuthorization(false));
  }
}
