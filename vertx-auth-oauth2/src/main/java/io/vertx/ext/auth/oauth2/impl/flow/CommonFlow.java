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
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.api;

/**
 * @author Paulo Lopes
 */
abstract class CommonFlow implements OAuth2Flow {

  protected final OAuth2AuthProviderImpl provider;
  protected final OAuth2ClientOptions config;

  CommonFlow(OAuth2AuthProviderImpl provider) {
    this.provider = provider;
    this.config = provider.getConfig();
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

    api(provider, HttpMethod.POST, config.getIntrospectionPath(), query, res -> {
      if (res.succeeded()) {
        try {
          final JsonObject json = res.result();
          // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations do not return this)
          if (json.containsKey("active") && !json.getBoolean("active", false)) {
            handler.handle(Future.failedFuture("Inactive Token"));
            return;
          }

          // validate client id
          if (json.containsKey("client_id") && !json.getString("client_id", "").equals(config.getClientID())) {
            handler.handle(Future.failedFuture("Wrong client_id"));
            return;
          }

          handler.handle(Future.succeededFuture(res.result()));
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      } else {
        handler.handle(Future.failedFuture(res.cause()));
      }
    });
  }
}
