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
 * Simplified factory to create an {@link OAuth2Auth} for Ory (Ory Network or a self hosted Ory Hydra).
 * <p>
 * Ory Hydra is a certified OpenID Connect provider. The endpoints below are taken from the Ory Hydra public API
 * reference (<a href="https://www.ory.com/docs/hydra/reference/api">https://www.ory.com/docs/hydra/reference/api</a>)
 * and the Ory OAuth2 authorization code flow guide
 * (<a href="https://www.ory.com/docs/oauth2-oidc/authorization-code-flow">https://www.ory.com/docs/oauth2-oidc/authorization-code-flow</a>).
 * <p>
 * The {@code site} is the base URL of the public API of your deployment:
 * <ul>
 *   <li>Ory Network: {@code https://{project-slug}.projects.oryapis.com}</li>
 *   <li>Self hosted Ory Hydra: the public port of Hydra, e.g.: {@code http://localhost:4444}</li>
 * </ul>
 * <p>
 * The {@code /userinfo} endpoint returns the standard OpenID Connect claims for the granted scopes
 * ({@code sub} always, plus e.g. {@code email}, {@code email_verified}, {@code name}, {@code preferred_username}
 * as populated by your consent app).
 * <p>
 * Notes:
 * <ul>
 *   <li>Token introspection lives on the Ory Hydra <b>admin</b> API ({@code /admin/oauth2/introspect}) which is
 *   not reachable with client credentials, so no introspection path is configured.</li>
 *   <li>Client credentials are sent using HTTP Basic authentication ({@code client_secret_basic}), which is the
 *   default {@code token_endpoint_auth_method} for Ory OAuth2 clients.</li>
 * </ul>
 */
@VertxGen
public interface OryAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Ory
   *
   * @param site         root URL for the provider without trailing slashes, eg. https://{project-slug}.projects.oryapis.com
   * @param clientId     the client id given to you by Ory
   * @param clientSecret the client secret given to you by Ory
   */
  static OAuth2Auth create(Vertx vertx, String site, String clientId, String clientSecret) {
    return create(vertx, site, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Ory
   *
   * @param site              root URL for the provider without trailing slashes, eg. https://{project-slug}.projects.oryapis.com
   * @param clientId          the client id given to you by Ory
   * @param clientSecret      the client secret given to you by Ory
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String site, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite(site)
        // https://www.ory.com/docs/hydra/reference/api (public endpoints)
        .setAuthorizationPath("/oauth2/auth")
        .setTokenPath("/oauth2/token")
        .setUserInfoPath("/userinfo")
        // RFC 7009
        .setRevocationPath("/oauth2/revoke")
        // OpenID Connect RP-Initiated Logout
        .setLogoutPath("/oauth2/sessions/logout")
        // RFC 7517
        .setJwkPath("/.well-known/jwks.json")
        .setScopeSeparator(" "));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the given site in the
   * configuration options and attempt to load the well known descriptor
   * ({@code {site}/.well-known/openid-configuration}).
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx  the vertx instance
   * @param config the initial config, the site must be set to the Ory public API base URL
   * @return future with instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    return OpenIDConnectAuth.discover(vertx, config);
  }
}
