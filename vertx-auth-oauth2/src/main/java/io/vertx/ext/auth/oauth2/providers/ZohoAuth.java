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

import java.util.Objects;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Zoho.
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
@VertxGen
public interface ZohoAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Zoho (default DC)
   *
   * @param clientId     the client id given to you by Zoho
   * @param clientSecret the client secret given to you by Zoho
   *
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String soid) {
    return create(vertx, "com", clientId, clientSecret, soid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Zoho
   *
   * @param dc                the data center to use (e.g. "com", "eu", "in", "us")
   * @param clientId          the client id given to you by Zoho
   * @param clientSecret      the client secret given to you by Zoho
   * @param soid              the soid of your application given to you by Zoho
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String dc, String clientId, String clientSecret, String soid, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite("https://accounts.zoho." + Objects.requireNonNull(dc))
        .setTokenPath("/oauth/v2/token")
        .setAuthorizationPath("/oauth/v2/auth")
        .setIntrospectionPath("/oauth/v2/introspect")
        .setUserInfoPath("/oauth/v2/userinfo")
        .setScopeSeparator(" ")
        .setExtraParameters(new JsonObject()
          .put("soid", Objects.requireNonNull(soid))));
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
   * @param soid   the soid of your application given to you by Zoho
   * @param config the initial config
   * @return future with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final String soid, final OAuth2Options config) {
    return discover(vertx, "com", soid, config);
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
   * @param dc     the data center to use (e.g. "com", "eu", "in", "us")
   * @param soid   the soid of your application given to you by Zoho
   * @param config the initial config
   * @return future with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final String dc, final String soid, final OAuth2Options config) {
    // don't override if already set
    final String site = config.getSite() == null ? "https://accounts.zoho." + Objects.requireNonNull(dc) : config.getSite();

    return OpenIDConnectAuth.discover(vertx,
      new OAuth2Options(config)
        .setSite(site)
        .setScopeSeparator(" ")
        .setExtraParameters(new JsonObject()
          .put("soid", Objects.requireNonNull(soid))));
  }
}
