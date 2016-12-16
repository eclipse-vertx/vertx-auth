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
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.api;

/**
 * @author Paulo Lopes
 */
abstract class CommonFlow implements OAuth2Flow {

  protected final OAuth2AuthProviderImpl provider;

  CommonFlow(OAuth2AuthProviderImpl provider) {
    this.provider = provider;
  }

  /**
   * Implement RFC7662 Token introspection.
   *
   * @param token the oauth2 token opaque string
   * @param tokenType hint
   * @param handler callback
   */
  @Override
  public void introspectToken(String token, String tokenType, Handler<AsyncResult<JsonObject>> handler) {

    final JsonObject query = new JsonObject()
      .put("token", token)
      .put("authorizationHeaderOnly", true);

    // optional param from RFC7662
    if (tokenType != null) {
      query.put("token_type_hint", tokenType);
    }

    api(provider, HttpMethod.POST, provider.getConfig().getIntrospectionPath(), query, res -> {
      if (res.succeeded()) {
        final JsonObject json = res.result();

        if (res.result().getBoolean("active", false)) {
          // validate client id
          if (json.containsKey("client_id") && !json.getString("client_id", "").equals(provider.getConfig().getClientID())) {
            handler.handle(Future.failedFuture("Wrong client_id"));
            return;
          }

          handler.handle(Future.succeededFuture(res.result()));
        } else {
          handler.handle(Future.failedFuture("Inactive Token"));
        }
      } else {
        handler.handle(Future.failedFuture(res.cause()));
      }
    });
  }
}
