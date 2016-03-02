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
package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;

import java.nio.charset.StandardCharsets;

/**
 * @author Paulo Lopes
 */
public class AccessTokenImpl extends AbstractUser implements AccessToken {

  private static final Logger log = LoggerFactory.getLogger(AccessTokenImpl.class);

  private Vertx vertx;
  private OAuth2ClientOptions config;

  private JsonObject token;

  /**
   * Creates an AccessToken instance.
   */
  public AccessTokenImpl() {
    // required if the object is serialized, however this is not a good idea
    // because JWT are supposed to be used in stateless environments
    log.info("You are probably serializing the OAuth2 User, OAuth2 tokens are supposed to be used in stateless servers!");
  }

  /**
   * Creates an AccessToken instance.
   * @param token - An object containing the token object returned from the OAuth2 server.
   */
  public AccessTokenImpl(Vertx vertx, OAuth2ClientOptions config, JsonObject token) {
    this.vertx = vertx;
    this.config = config;

    init(token);
  }

  private void init(JsonObject token) {
    if (token.containsKey("expires_in")) {
      token = token.copy();
      token.put("expires_at", System.currentTimeMillis() + 1000 * token.getLong("expires_in"));
    }

    this.token = token;
  }

  /**
   * Check if the access token is expired or not.
   */
  @Override
  public boolean expired() {
    return token.containsKey("expires_at") && token.getLong("expires_at", 0l) < System.currentTimeMillis();
  }

  /**
   * Refresh the access token
   *
   * @param callback - The callback function returning the results.
   */
  @Override
  public AccessTokenImpl refresh(Handler<AsyncResult<Void>> callback) {
    JsonObject params = new JsonObject()
        .put("grant_type", "refresh_token")
        .put("refresh_token", token.getString("refresh_token"));

    OAuth2API.api(vertx, config, HttpMethod.POST, config.getTokenPath(), params, res -> {
      if (res.succeeded()) {
        init(res.result());
        callback.handle(Future.succeededFuture());
      } else {
        callback.handle(Future.failedFuture(res.cause()));
      }
    });

    return this;
  }

  /**
   * Revoke access or refresh token
   *
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   */
  @Override
  public AccessTokenImpl revoke(String token_type, Handler<AsyncResult<Void>> callback) {

    String token = "access_token".equals(token_type) ? this.token.getString("access_token") : this.token.getString("refresh_token");

    JsonObject params = new JsonObject()
        .put("token", token)
        .put("token_type_hint", token_type);

    OAuth2API.api(vertx, config, HttpMethod.POST, config.getRevocationPath(), params, res -> {
      if (res.succeeded()) {
        // TODO: what to do with the result from this call?
        callback.handle(Future.succeededFuture());
      } else {
        callback.handle(Future.failedFuture(res.cause()));
      }
    });

    return this;
  }

  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    resultHandler.handle(Future.succeededFuture(true));
  }

  @Override
  public JsonObject principal() {
    return token;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    final OAuth2AuthProviderImpl provider = (OAuth2AuthProviderImpl) authProvider;

    vertx = provider.getVertx();
    config = provider.getConfig();
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes = token.encode().getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len = buffer.getInt(pos);
    pos += 4;
    byte[] bytes = buffer.getBytes(pos, pos + len);
    token = new JsonObject(new String(bytes, StandardCharsets.UTF_8));
    pos += len;

    return pos;
  }
}
