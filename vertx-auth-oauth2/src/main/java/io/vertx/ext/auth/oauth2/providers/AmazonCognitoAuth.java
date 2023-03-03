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
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Amazon Cognito.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface AmazonCognitoAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Amazon Cognito
   *
   * @param region       the region to use
   * @param clientId     the client id given to you by Amazon Cognito
   * @param clientSecret the client secret given to you by Amazon Cognito
   * @param guid         the guid of your application given to you by Amazon Cognito
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String guid) {
    return create(vertx, region, clientId, clientSecret, guid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Amazon Cognito
   *
   * @param region            the region to use
   * @param clientId          the client id given to you by Amazon Cognito
   * @param clientSecret      the client secret given to you by Amazon Cognito
   * @param userPoolId        the userPoolId of your application given to you by Amazon Cognito
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String userPoolId, HttpClientOptions httpClientOptions) {
    if (region == null) {
      throw new IllegalStateException("region cannot be null");
    }

    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(userPoolId)
        .setSite("https://cognito-idp." + region + ".amazonaws.com/{tenant}")
        .setTokenPath("/oauth2/token")
        .setAuthorizationPath("/oauth2/authorize")
        .setUserInfoPath("/oauth2/userInfo")
        .setJwkPath("/.well-known/jwks.json")
        .setLogoutPath("/logout")
        .setScopeSeparator("+"));
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
   * @param vertx  the vertx instance
   * @param config the initial config
   * @return future with instantiated Oauth2 provider instance handler
   * @see AmazonCognitoAuth#discover(Vertx, OAuth2Options, Handler)
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    return OpenIDConnectAuth.discover(
        vertx,
        new OAuth2Options(config)
          .setScopeSeparator("+"));
  }
}
