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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
abstract class AbstractOAuth2Flow implements OAuth2Flow {

  protected final Vertx vertx;
  protected final OAuth2ClientOptions config;

  AbstractOAuth2Flow(Vertx vertx, OAuth2ClientOptions config) {
    this.vertx = vertx;
    this.config = config;
  }

  static void throwIfNull(String key, Object value) throws IllegalArgumentException {
    if (value == null) {
      throw new IllegalArgumentException("Configuration missing. You need to specify [" + key + "]");
    }
  }

  void getToken(String grantType, JsonObject params, Handler<AsyncResult<JsonObject>> handler) {

    final JsonObject headers = new JsonObject();

    if (config.isUseBasicAuthorizationHeader()) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    // Enable the system to send authorization params in the body (for example github does not require to be in the header)
    final JsonObject form = params.copy();
    if (config.getExtraParameters() != null) {
      form.mergeIn(config.getExtraParameters());
    }

    form.put("client_id", config.getClientID());
    form.put("grant_type", grantType);

    if (config.getClientSecretParameterName() != null) {
      form.put(config.getClientSecretParameterName(), config.getClientSecret());
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));

    // specify preferred accepted content type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    fetch(
      vertx,
      config,
      HttpMethod.POST,
      config.getTokenPath(),
      headers,
      payload,
      res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final OAuth2Response reply = res.result();

        if (reply.body() == null || reply.body().length() == 0) {
          handler.handle(Future.failedFuture("No Body"));
          return;
        }

        JsonObject json;

        if (reply.is("application/json")) {
          try {
            json = reply.jsonObject();
          } catch (RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            json = queryToJSON(reply.body().toString());
          } catch (UnsupportedEncodingException | RuntimeException e) {
            handler.handle(Future.failedFuture(e));
            return;
          }
        } else {
          handler.handle(Future.failedFuture("Cannot handle content type: " + reply.headers().get("Content-Type")));
          return;
        }

        try {
          if (json.containsKey("error")) {
            String description;
            Object error = json.getValue("error");
            if (error instanceof JsonObject) {
              description = ((JsonObject) error).getString("message");
            } else {
              // attempt to handle the error as a string
              try {
                description = json.getString("error_description", json.getString("error"));
              } catch (RuntimeException e) {
                description = error.toString();
              }
            }
            handler.handle(Future.failedFuture(description));
          } else {
            handler.handle(Future.succeededFuture(json));
          }
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });
  }
}
