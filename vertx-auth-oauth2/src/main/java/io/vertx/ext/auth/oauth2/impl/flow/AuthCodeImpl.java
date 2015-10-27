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
package io.vertx.ext.auth.oauth2.impl.flow;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.impl.AccessTokenImpl;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
public class AuthCodeImpl implements OAuth2Flow {

  private final Vertx vertx;
  private final JsonObject config;

  public AuthCodeImpl(Vertx vertx, JsonObject config) {
    this.vertx = vertx;
    this.config = config;
  }

  /**
   * Redirect the user to the authorization page
   * @param params  - redirectURI: A String that represents the registered application URI where the user is redirected after authorization.
   *                  scope:       A String that represents the application privileges.
   *                  state:       A String that represents an optional opaque value used by the client to maintain state between the request and the callback.
   */
  @Override
  public String authorizeURL(JsonObject params) {
    params.put("response_type", "code");
    params.put("client_id", config.getString("clientID"));

    return config.getString("site") + config.getString("authorizationPath") + '?' + stringify(params);
  }

  /**
   * Returns the Access Token object.
   *
   * @param params - code:        Authorization code (from previous step).
   *                 redirectURI: A String that represents the callback uri.
   * @param handler - The handler returning the results.
   */
  @Override
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler) {
    params.put("grant_type", "authorization_code");
    api(vertx, config, HttpMethod.POST, config.getString("tokenPath"), params, res -> {
      if (res.succeeded()) {
        handler.handle(Future.succeededFuture(new AccessTokenImpl(vertx, config, res.result())));
      } else {
        handler.handle(Future.failedFuture(res.cause()));
      }
    });
  }
}
