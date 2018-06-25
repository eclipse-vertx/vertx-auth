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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Response;
import io.vertx.ext.auth.oauth2.impl.OAuth2API;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.impl.OAuth2TokenImpl;

import java.io.UnsupportedEncodingException;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
public class AuthJWTImpl extends AbstractOAuth2Flow implements OAuth2Flow {

  private final OAuth2AuthProviderImpl provider;

  public AuthJWTImpl(OAuth2AuthProviderImpl provider) {
    super(provider.getVertx(), provider.getConfig());
    this.provider = provider;
    // validation
    throwIfNull("clientId", config.getClientID());
    throwIfNull("pubSecKeys", config.getPubSecKeys());
    if (config.getPubSecKeys().size() == 0) {
      throwIfNull("pubSecKey", null);
    }
  }

  /**
   * Returns the Access Token object.
   *
   * @param params - jwt: a JWT to be traded for a token
   * @param callback- The handler returning the results.
   */
  @Override
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> callback) {

    final JsonObject body = new JsonObject()
      .put("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
      .put("assertion", provider.getJWT().sign(params, provider.getConfig().getJWTOptions()));

    fetch(
      provider.getVertx(),
      provider.getConfig(),
      HttpMethod.POST,
      provider.getConfig().getTokenPath(),
      new JsonObject().put("Content-Type", "application/x-www-form-urlencoded"),
      Buffer.buffer(OAuth2API.stringify(body)),
      fetch -> {
        if (fetch.failed()) {
          callback.handle(Future.failedFuture(fetch.cause()));
          return;
        }

        final OAuth2Response res = fetch.result();

        // token is expected to be an object
        JsonObject token;

        if (res.is("application/json")) {
          try {
            // userInfo is expected to be an object
            token = res.jsonObject();
          } catch (RuntimeException e) {
            callback.handle(Future.failedFuture(e));
            return;
          }
        } else if (res.is("application/x-www-form-urlencoded") || res.is("text/plain")) {
          try {
            // attempt to convert url encoded string to json
            token = OAuth2API.queryToJSON(res.body().toString());
          } catch (RuntimeException | UnsupportedEncodingException e) {
            callback.handle(Future.failedFuture(e));
            return;
          }
        } else {
          callback.handle(Future.failedFuture("Cannot handle Content-Type: " + res.headers().get("Content-Type")));
          return;
        }

        callback.handle(Future.succeededFuture(new OAuth2TokenImpl(provider, token)));
      });
  }
}
