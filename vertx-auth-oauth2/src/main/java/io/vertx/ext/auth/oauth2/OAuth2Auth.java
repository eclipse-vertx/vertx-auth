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

package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Auth extends AuthProvider {

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config) {
    return new OAuth2AuthProviderImpl(vertx, flow, config);
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow) {
    return new OAuth2AuthProviderImpl(vertx, flow, new JsonObject());
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   */
  String authorizeURL(JsonObject params);

  /**
   * Returns the Access Token object.
   *
   * @param params - JSON with the options, each flow requires different options.
   * @param handler - The handler returning the results.
   */
  void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Call OAuth2 APIs.
   *
   * @param method HttpMethod
   * @param path target path
   * @param params parameters
   * @param handler handler
   * @return self
   */
  @Fluent
  OAuth2Auth api(HttpMethod method, String path, JsonObject params, Handler<AsyncResult<JsonObject>> handler);
}