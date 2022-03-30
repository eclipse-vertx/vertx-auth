/*
 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Gitee.
 *
 * @author <a href="mailto:gitee@oschina.cn">Gitee</a>
 */
@VertxGen
public interface GiteeAuth {

  /**
   * Create a OAuth2Auth provider for Gitee
   *
   * @param clientId     the client id given to you by Gitee
   * @param clientSecret the client secret given to you by Gitee
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Gitee
   *
   * @param clientId          the client id given to you by Gitee
   * @param clientSecret      the client secret given to you by Gitee
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setSite("https://gitee.com")
        .setTokenPath("/oauth/token")
        .setAuthorizationPath("/oauth/authorize")
        .setUserInfoPath("https://gitee.com/api/v5/user")
        .setHeaders(new JsonObject().put("User-Agent", "vertx-auth-oauth2")));
  }
}
