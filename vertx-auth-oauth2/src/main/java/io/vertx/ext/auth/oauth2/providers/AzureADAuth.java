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
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Azure AD.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface AzureADAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Microsoft Azure Active Directory
   *
   * @param clientId     the client id given to you by Azure
   * @param clientSecret the client secret given to you by Azure
   * @param guid         the guid of your application given to you by Azure
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String guid) {
    return create(vertx, clientId, clientSecret, guid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Microsoft Azure Active Directory
   *
   * @param clientId          the client id given to you by Azure
   * @param clientSecret      the client secret given to you by Azure
   * @param guid              the guid of your application given to you by Azure
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String guid, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(guid)
        .setSite("https://login.microsoftonline.com/{tenant}")
        .setTokenPath("/oauth2/token")
        .setAuthorizationPath("/oauth2/authorize")
        .setJwkPath("/../common/discovery/keys")
        .setJWTOptions(new JWTOptions()
          .setNonceAlgorithm("SHA-256")));
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
    final String site = config.getSite() == null ? "https://login.microsoftonline.com/{tenant}" : config.getSite();
    final JWTOptions jwtOptions = config.getJWTOptions() == null ? new JWTOptions() : new JWTOptions(config.getJWTOptions());
    // azure jwt options defaults
    if (jwtOptions.getNonceAlgorithm() == null) {
      jwtOptions.setNonceAlgorithm("SHA-256");
    }

    return OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options(config)
        // Azure OpenId does not return the same url where the request was sent to
        .setValidateIssuer(false)
        .setSite(site)
        .setJWTOptions(jwtOptions));
  }
}
