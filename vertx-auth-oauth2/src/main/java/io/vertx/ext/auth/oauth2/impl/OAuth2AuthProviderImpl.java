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
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWT;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.impl.flow.*;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth {

  private final Vertx vertx;
  private final OAuth2ClientOptions config;
  private final JWT jwt;

  private final OAuth2Flow flow;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) {
    this.vertx = vertx;
    this.config = config;

    switch (flow) {
      case AUTH_CODE:
        jwt = new JWT(config.getPublicKey(), false);
        this.flow = new AuthCodeImpl(this);
        break;
      case CLIENT:
        jwt = new JWT(config.getPublicKey(), false);
        this.flow = new ClientImpl(this);
        break;
      case PASSWORD:
        jwt = new JWT(config.getPublicKey(), false);
        this.flow = new PasswordImpl(this);
        break;
      case AUTH_JWT:
        jwt = new JWT(config.getPrivateKey(), true);
        this.flow = new AuthJWTImpl(this);
        break;
      default:
        throw new IllegalArgumentException("Invalid oauth2 flow type: " + flow);
    }
  }

  public OAuth2ClientOptions getConfig() {
    return config;
  }

  public Vertx getVertx() {
    return vertx;
  }

  public JsonObject decode(String token) {
    return jwt.decode(token);
  }

  public String sign(JsonObject payload) {
    return jwt.sign(payload, config.getExtraParameters());
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    resultHandler.handle(Future.failedFuture("JWT cannot be used for AuthN"));
  }

  @Override
  public String authorizeURL(JsonObject params) {
    return flow.authorizeURL(params);
  }

  @Override
  public void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler) {
    flow.getToken(params, handler);
  }

  @Override
  public OAuth2Auth api(HttpMethod method, String path, JsonObject params, Handler<AsyncResult<JsonObject>> handler) {
    OAuth2API.api(this, method, path, params, handler);
    return this;
  }

  @Override
  public boolean hasJWTToken() {
    return config.isJwtToken();
  }

  @Override
  public String getScopeSeparator() {
    final String sep = config.getScopeSeparator();
    return sep == null ? " " : sep;
  }
}
