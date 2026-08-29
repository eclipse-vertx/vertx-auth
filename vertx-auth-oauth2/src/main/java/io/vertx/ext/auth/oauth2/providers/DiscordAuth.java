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
 * Simplified factory to create an {@link OAuth2Auth} for Discord.
 * <p>
 * The OAuth2 endpoints are documented at
 * <a href="https://docs.discord.com/developers/topics/oauth2">https://docs.discord.com/developers/topics/oauth2</a>.
 * <p>
 * The user info endpoint is {@code GET /users/@me}
 * (<a href="https://docs.discord.com/developers/resources/user#get-current-user">https://docs.discord.com/developers/resources/user#get-current-user</a>)
 * and requires the {@code identify} scope. It returns a user object with, among others, {@code id},
 * {@code username}, {@code discriminator}, {@code global_name}, {@code avatar}, {@code banner},
 * {@code accent_color}, {@code locale}, {@code mfa_enabled}, {@code flags}, {@code public_flags}, and
 * {@code email}, {@code verified} when the {@code email} scope is also granted.
 */
@VertxGen
public interface DiscordAuth {

  /**
   * Create a OAuth2Auth provider for Discord
   *
   * @param clientId     the client id given to you by Discord
   * @param clientSecret the client secret given to you by Discord
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Discord
   *
   * @param clientId          the client id given to you by Discord
   * @param clientSecret      the client secret given to you by Discord
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite("https://discord.com/api")
        // https://docs.discord.com/developers/topics/oauth2#shared-resources-oauth2-urls
        .setAuthorizationPath("https://discord.com/oauth2/authorize")
        .setTokenPath("/oauth2/token")
        .setRevocationPath("/oauth2/token/revoke")
        // https://docs.discord.com/developers/resources/user#get-current-user
        .setUserInfoPath("/users/@me")
        .setScopeSeparator(" "));
  }
}
