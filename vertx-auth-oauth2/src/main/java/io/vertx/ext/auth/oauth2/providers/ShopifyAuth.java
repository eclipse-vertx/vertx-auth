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
 * Simplified factory to create an {@link OAuth2Auth} for Shopify.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface ShopifyAuth {

  /**
   * Create a OAuth2Auth provider for Shopify
   *
   * @param clientId     the client id given to you by Shopify
   * @param clientSecret the client secret given to you by Shopify
   * @param shop         your shop name
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String shop) {
    return create(vertx, clientId, clientSecret, shop, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Shopify
   *
   * @param clientId          the client id given to you by Shopify
   * @param clientSecret      the client secret given to you by Shopify
   * @param shop              your shop name
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String shop, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(shop)
        .setSite("https://{tenant}.myshopify.com")
        .setTokenPath("/admin/oauth/access_token")
        .setAuthorizationPath("/admin/oauth/authorize")
        .setUserInfoPath("/admin/shop.json")
        .setScopeSeparator(","));
  }
}
