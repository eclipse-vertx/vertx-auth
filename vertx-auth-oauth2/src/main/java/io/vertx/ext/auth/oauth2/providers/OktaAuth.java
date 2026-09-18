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
 * Simplified factory to create an {@link OAuth2Auth} for Okta.
 * <p>
 * Okta exposes two kinds of OpenID Connect authorization servers
 * (<a href="https://developer.okta.com/docs/concepts/auth-servers/">https://developer.okta.com/docs/concepts/auth-servers/</a>):
 * <ul>
 *   <li>the <b>org authorization server</b>: {@code https://{yourOktaDomain}/oauth2/v1/...} with issuer
 *   {@code https://{yourOktaDomain}}, used when no authorization server id is given;</li>
 *   <li>a <b>custom authorization server</b>: {@code https://{yourOktaDomain}/oauth2/{authorizationServerId}/v1/...}
 *   with issuer {@code https://{yourOktaDomain}/oauth2/{authorizationServerId}} (the pre-configured one is named
 *   {@code default}).</li>
 * </ul>
 * The endpoint paths are documented in the Okta OpenID Connect &amp; OAuth 2.0 API reference:
 * <a href="https://developer.okta.com/docs/reference/api/oidc/">https://developer.okta.com/docs/reference/api/oidc/</a>.
 * <p>
 * The {@code /userinfo} endpoint returns the OpenID Connect claims for the granted scopes: {@code sub} always;
 * {@code name}, {@code nickname}, {@code preferred_username}, {@code given_name}, {@code middle_name},
 * {@code family_name}, {@code picture}, {@code website}, {@code gender}, {@code birthdate}, {@code zoneinfo},
 * {@code locale}, {@code updated_at} for {@code profile}; {@code email}, {@code email_verified} for {@code email};
 * {@code address} for {@code address}; {@code phone_number} for {@code phone}.
 * <p>
 * Client credentials are sent using HTTP Basic authentication ({@code client_secret_basic}), Okta's default
 * token endpoint authentication method
 * (<a href="https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth/">https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth/</a>).
 */
@VertxGen
public interface OktaAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Okta using the org authorization server.
   *
   * @param clientId     the client id given to you by Okta
   * @param clientSecret the client secret given to you by Okta
   * @param domain       your Okta domain, eg. {@code dev-123456.okta.com}
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String domain) {
    return create(vertx, clientId, clientSecret, domain, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Okta using the org authorization server.
   *
   * @param clientId          the client id given to you by Okta
   * @param clientSecret      the client secret given to you by Okta
   * @param domain            your Okta domain, eg. {@code dev-123456.okta.com}
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String domain, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(domain)
        // https://developer.okta.com/docs/concepts/auth-servers/#org-authorization-server
        .setSite("https://{tenant}")
        // https://developer.okta.com/docs/reference/api/oidc/#endpoints
        .setAuthorizationPath("/oauth2/v1/authorize")
        .setTokenPath("/oauth2/v1/token")
        .setUserInfoPath("/oauth2/v1/userinfo")
        // RFC 7009
        .setRevocationPath("/oauth2/v1/revoke")
        // RFC 7662
        .setIntrospectionPath("/oauth2/v1/introspect")
        // RFC 7517
        .setJwkPath("/oauth2/v1/keys")
        .setLogoutPath("/oauth2/v1/logout")
        .setScopeSeparator(" "));
  }

  /**
   * Create a OAuth2Auth provider for Okta using a custom authorization server.
   *
   * @param clientId              the client id given to you by Okta
   * @param clientSecret          the client secret given to you by Okta
   * @param domain                your Okta domain, eg. {@code dev-123456.okta.com}
   * @param authorizationServerId the custom authorization server id, eg. {@code default}
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String domain, String authorizationServerId) {
    return create(vertx, clientId, clientSecret, domain, authorizationServerId, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Okta using a custom authorization server.
   *
   * @param clientId              the client id given to you by Okta
   * @param clientSecret          the client secret given to you by Okta
   * @param domain                your Okta domain, eg. {@code dev-123456.okta.com}
   * @param authorizationServerId the custom authorization server id, eg. {@code default}
   * @param httpClientOptions     custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String domain, String authorizationServerId, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(domain)
        // https://developer.okta.com/docs/concepts/auth-servers/#custom-authorization-server
        .setSite("https://{tenant}/oauth2/" + authorizationServerId)
        // https://developer.okta.com/docs/reference/api/oidc/#endpoints
        .setAuthorizationPath("/v1/authorize")
        .setTokenPath("/v1/token")
        .setUserInfoPath("/v1/userinfo")
        // RFC 7009
        .setRevocationPath("/v1/revoke")
        // RFC 7662
        .setIntrospectionPath("/v1/introspect")
        // RFC 7517
        .setJwkPath("/v1/keys")
        .setLogoutPath("/v1/logout")
        .setScopeSeparator(" "));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the site in the
   * configuration options and attempt to load the well known descriptor. The site is the issuer of the
   * authorization server, either {@code https://{yourOktaDomain}} (org authorization server) or
   * {@code https://{yourOktaDomain}/oauth2/{authorizationServerId}} (custom authorization server).
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx  the vertx instance
   * @param config the initial config
   * @return future with instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    return OpenIDConnectAuth.discover(vertx, config);
  }
}
