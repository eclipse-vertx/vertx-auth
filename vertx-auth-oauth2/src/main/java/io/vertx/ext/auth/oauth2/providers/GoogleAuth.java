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
import io.vertx.core.*;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.JWTOptions;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for Google.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface GoogleAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId     the client id given to you by Google
   * @param clientSecret the client secret given to you by Google
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId          the client id given to you by Google
   * @param clientSecret      the client secret given to you by Google
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite("https://accounts.google.com")
        .setTokenPath("https://accounts.google.com/o/oauth2/token")
        .setAuthorizationPath("https://accounts.google.com/o/oauth2/auth")
        .setIntrospectionPath("https://accounts.google.com/o/oauth2/tokeninfo")
        .setUserInfoPath("https://www.googleapis.com/oauth2/v1/userinfo")
        .setJwkPath("https://www.googleapis.com/oauth2/v3/certs")
        .setRevocationPath("https://oauth2.googleapis.com/revoke")
        .setUserInfoParameters(new JsonObject()
          .put("alt", "json")));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx   the vertx instance
   * @param config  the initial config
   * @param handler the instantiated Oauth2 provider instance handler
   */
  @Deprecated
  static void discover(final Vertx vertx, final OAuth2Options config, final Handler<AsyncResult<OAuth2Auth>> handler) {
    discover(vertx, config)
      .onComplete(handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @see GoogleAuth#discover(Vertx, OAuth2Options, Handler)
   * @param vertx   the vertx instance
   * @param config  the initial config
   * @return future with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    // don't override if already set
    final String site = config.getSite() == null ? "https://accounts.google.com" : config.getSite();

    return OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options(config)
        .setSite(site)
        .setUserInfoParameters(new JsonObject()
          .put("alt", "json")));
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson) {
    return create(vertx, serviceAccountJson, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   * @param httpClientOptions  custom http client options
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(serviceAccountJson.getString("client_id"))
        .setSite("https://accounts.google.com")
        .setTokenPath(serviceAccountJson.getString("token_uri"))
        .addPubSecKey(new PubSecKeyOptions()
          .setAlgorithm("RS256")
          .setId(serviceAccountJson.getString("private_key_id"))
          .setBuffer(serviceAccountJson.getString("private_key")))
        .setJWTOptions(new JWTOptions()
          .setAlgorithm("RS256")
          .setExpiresInMinutes(60)
          .addAudience(serviceAccountJson.getString("token_uri"))
          .setIssuer(serviceAccountJson.getString("client_email"))));
  }
}
