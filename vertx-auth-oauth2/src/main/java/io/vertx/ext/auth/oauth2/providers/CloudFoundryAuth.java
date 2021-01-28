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
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for CloudFoundry UAA.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface CloudFoundryAuth {

  /**
   * Create a OAuth2Auth provider for CloudFoundry UAA
   *
   * @param clientId     the client id given to you by CloudFoundry UAA
   * @param clientSecret the client secret given to you by CloudFoundry UAA
   * @param uuaURL         the url to your UUA server instance
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String uuaURL) {
    return create(vertx, clientId, clientSecret, uuaURL, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for CloudFoundry UAA
   *
   * @param clientId          the client id given to you by CloudFoundry UAA
   * @param clientSecret      the client secret given to you by CloudFoundry UAA
   * @param uuaURL            the url to your UUA server instance
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String uuaURL, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientID(clientId)
        .setClientSecret(clientSecret)
        .setSite(uuaURL)
        .setTokenPath("/oauth/token")
        .setAuthorizationPath("/oauth/authorize"));
  }
}
