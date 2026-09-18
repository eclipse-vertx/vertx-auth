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
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Spotify.
 * <p>
 * The OAuth2 endpoints are documented in the Spotify authorization code flow guide
 * (<a href="https://developer.spotify.com/documentation/web-api/tutorials/code-flow">https://developer.spotify.com/documentation/web-api/tutorials/code-flow</a>).
 * The token endpoint authenticates the client with an HTTP Basic {@code Authorization} header, which is the
 * default behaviour of this module.
 * <p>
 * The user info endpoint is {@code GET https://api.spotify.com/v1/me}
 * (<a href="https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile">https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile</a>)
 * and returns, among others, {@code id}, {@code display_name}, {@code uri}, {@code href}, {@code images},
 * {@code followers}, {@code external_urls}; {@code country}, {@code product}, {@code explicit_content} require the
 * {@code user-read-private} scope and {@code email} requires the {@code user-read-email} scope.
 */
@VertxGen
public interface SpotifyAuth {

  /**
   * Create a OAuth2Auth provider for Spotify
   *
   * @param clientId     the client id given to you by Spotify
   * @param clientSecret the client secret given to you by Spotify
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Spotify
   *
   * @param clientId          the client id given to you by Spotify
   * @param clientSecret      the client secret given to you by Spotify
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        // https://developer.spotify.com/documentation/web-api/tutorials/code-flow
        .setSite("https://accounts.spotify.com")
        .setAuthorizationPath("/authorize")
        .setTokenPath("/api/token")
        // https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile
        .setUserInfoPath("https://api.spotify.com/v1/me")
        .setScopeSeparator(" "));
  }
}
