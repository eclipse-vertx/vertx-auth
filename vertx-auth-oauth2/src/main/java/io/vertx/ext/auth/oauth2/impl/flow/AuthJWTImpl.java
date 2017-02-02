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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.impl.AccessTokenImpl;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
public class AuthJWTImpl implements OAuth2Flow {

  private final OAuth2AuthProviderImpl provider;

  public AuthJWTImpl(OAuth2AuthProviderImpl provider) {
    this.provider = provider;
  }

  /**
   * Returns the Access Token object.
   *
   * @param params - jwt: a JWT to be traded for a token
   * @param handler - The handler returning the results.
   */
  @Override
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler) {

    final JsonObject query = new JsonObject()
      .put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
      .put("assertion", provider.sign(params));

    post(provider, provider.getConfig().getTokenPath(), query, res -> {
      if (res.succeeded()) {
        try {
          handler.handle(Future.succeededFuture(new AccessTokenImpl(provider, res.result())));
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      } else {
        handler.handle(Future.failedFuture(res.cause()));
      }
    });
  }

  @Override
  public void introspectToken(String token, String tokenType, Handler<AsyncResult<JsonObject>> handler) {
    handler.handle(Future.failedFuture(new UnsupportedOperationException()));
  }
}
