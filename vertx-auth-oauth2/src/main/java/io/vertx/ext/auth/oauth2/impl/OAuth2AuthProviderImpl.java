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
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.impl.crypto.TokenVerifier;
import io.vertx.ext.auth.oauth2.impl.flow.OAuth2Flow;
import io.vertx.ext.auth.oauth2.impl.flow.AuthCodeImpl;
import io.vertx.ext.auth.oauth2.impl.flow.ClientImpl;
import io.vertx.ext.auth.oauth2.impl.flow.PasswordImpl;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth {

  private final Vertx vertx;
  private final OAuth2ClientOptions config;
  private final TokenVerifier verifier;

  private final OAuth2Flow flow;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) {
    this.vertx = vertx;
    this.config = config;
    verifier = new TokenVerifier(config.getPublicKey());

    switch (flow) {
      case AUTH_CODE:
        this.flow = new AuthCodeImpl(this);
        break;
      case CLIENT:
        this.flow = new ClientImpl(this);
        break;
      case PASSWORD:
        this.flow = new PasswordImpl(this);
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

  public TokenVerifier getVerifier() {
    return verifier;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {

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
}
