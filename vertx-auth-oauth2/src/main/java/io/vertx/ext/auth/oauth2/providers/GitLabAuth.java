/*
 * Copyright 2020 Red Hat, Inc.
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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for GitLab.com.
 *
 * <a href="https://gitlab.com/help/api/oauth2.md">https://gitlab.com/help/api/oauth2.md</a>
 */
@VertxGen
public interface GitLabAuth {

  /**
   * Create a OAuth2Auth provider for GitLab.com.
   *
   * @param clientId the client id given to you by GitLab
   * @param clientSecret the client secret given to you by GitLab
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, "https://gitlab.com", clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for GitLab.
   *
   * This method allows to specify custom GitLab domain.
   *
   * @param site root URL for the provider without trailing slashes, eg. https://gitlab.com
   * @param clientId the client id given to you by GitLab
   * @param clientSecret the client secret given to you by GitLab
   */
  static OAuth2Auth create(Vertx vertx, String site, String clientId, String clientSecret) {
    return create(vertx, site, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for GitLab.
   *
   * @param site root URL for the provider without trailing slashes, eg. https://gitlab.com
   * @param clientId the client id given to you by GitLab
   * @param clientSecret the client secret given to you by GitLab
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String site, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientID(clientId)
        .setClientSecret(clientSecret)
        .setSite(site)
        .setTokenPath("/oauth/token")
        .setAuthorizationPath("/oauth/authorize")
        .setUserInfoPath("/api/v4/user")
        .setScopeSeparator(" ")
        .setHeaders(new JsonObject()
          .put("User-Agent", "vertx-auth-oauth2")));
  }
}
