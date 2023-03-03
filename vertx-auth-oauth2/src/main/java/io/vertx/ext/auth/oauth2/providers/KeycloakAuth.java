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
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Keycloak.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface KeycloakAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param config the json config file exported from Keycloak admin console
   */
  static OAuth2Auth create(Vertx vertx, JsonObject config) {
    return create(vertx, OAuth2FlowType.AUTH_CODE, config);
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param flow   the oauth2 flow to use
   * @param config the json config file exported from Keycloak admin console
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config) {
    return create(vertx, flow, config, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param config            the json config file exported from Keycloak admin console
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, JsonObject config, HttpClientOptions httpClientOptions) {
    return create(vertx, OAuth2FlowType.AUTH_CODE, config, httpClientOptions);
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param flow              the oauth2 flow to use
   * @param config            the json config file exported from Keycloak admin console
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config, HttpClientOptions httpClientOptions) {
    final OAuth2Options options = new OAuth2Options()
      .setHttpClientOptions(httpClientOptions);

    options.setFlow(flow);

    if (config.containsKey("resource")) {
      options.setClientId(config.getString("resource"));
    }

    // keycloak conversion to oauth2 options
    if (config.containsKey("auth-server-url")) {
      options.setSite(config.getString("auth-server-url"));
    }

    if (config.containsKey("credentials") && config.getJsonObject("credentials").containsKey("secret")) {
      options.setClientSecret(config.getJsonObject("credentials").getString("secret"));
    }

    if (config.containsKey("realm")) {
      final String realm = config.getString("realm");

      options.setAuthorizationPath("/realms/" + realm + "/protocol/openid-connect/auth");
      options.setTokenPath("/realms/" + realm + "/protocol/openid-connect/token");
      options.setRevocationPath(null);
      options.setLogoutPath("/realms/" + realm + "/protocol/openid-connect/logout");
      options.setUserInfoPath("/realms/" + realm + "/protocol/openid-connect/userinfo");
      // keycloak follows the RFC7662
      options.setIntrospectionPath("/realms/" + realm + "/protocol/openid-connect/token/introspect");
      // keycloak follows the RFC7517
      options.setJwkPath("/realms/" + realm + "/protocol/openid-connect/certs");
    }

    if (config.containsKey("realm-public-key")) {
      options.addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setBuffer(
          // wrap the key with the right boundaries:
          "-----BEGIN PUBLIC KEY-----\n" +
          config.getString("realm-public-key") +
          "\n-----END PUBLIC KEY-----\n"
      ));
    }

    return OAuth2Auth
      .create(vertx, options);
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
   * @see KeycloakAuth#discover(Vertx, OAuth2Options, Handler)
   * @param vertx   the vertx instance
   * @param config  the initial config
   * @return promise with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    return OpenIDConnectAuth.discover(vertx, config);
  }
}
