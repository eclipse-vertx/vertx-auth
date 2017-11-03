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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.impl.flow.*;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth {

  private final Vertx vertx;
  private final OAuth2FlowType flowType;
  private final OAuth2ClientOptions config;
  private final JWT jwt = new JWT();

  private final OAuth2Flow flow;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) {
    this.vertx = vertx;
    this.config = config;
    this.flowType = flow;

    if (config.getPubSecKey() != null) {
      if (config.getPubSecKey().getPublicKey() != null || config.getPubSecKey().getSecretKey() != null) {
        jwt.addKeyPair(config.getPubSecKey().getType(), config.getPubSecKey().getPublicKey(), config.getPubSecKey().getSecretKey());
      }
    }

    switch (flow) {
      case AUTH_CODE:
        if (config.getClientID() == null || config.getClientSecret() == null || config.getSite() == null) {
          throw new IllegalArgumentException("Configuration missing. You need to specify the client id, the client secret and the oauth2 server");
        }
        this.flow = new AuthCodeImpl(this);
        break;
      case CLIENT:
        if (config.getClientID() == null || config.getClientSecret() == null || config.getSite() == null) {
          throw new IllegalArgumentException("Configuration missing. You need to specify the client id, the client secret and the oauth2 server");
        }
        this.flow = new ClientImpl(this);
        break;
      case PASSWORD:
        if (config.getClientID() == null || config.getClientSecret() == null || config.getSite() == null) {
          throw new IllegalArgumentException("Configuration missing. You need to specify the client id, the client secret and the oauth2 server");
        }
        this.flow = new PasswordImpl(this);
        break;
      case AUTH_JWT:
        if (config.getPubSecKey() == null || config.getPubSecKey().getSecretKey() == null || config.getPubSecKey().getType() == null || config.getSite() == null) {
          throw new IllegalArgumentException("Configuration missing. You need to specify the private key, the key type and the oauth2 server");
        }
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

  public JWT getJWT() {
    return jwt;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    flow.getToken(authInfo, getToken -> {
      if (getToken.failed()) {
        resultHandler.handle(Future.failedFuture(getToken.cause()));
      } else {
        resultHandler.handle(Future.succeededFuture(getToken.result()));
      }
    });
  }

  @Override
  public String authorizeURL(JsonObject params) {
    return flow.authorizeURL(params);
  }

  @Override
  public void getToken(JsonObject credentials, Handler<AsyncResult<AccessToken>> handler) {
    flow.getToken(credentials, handler);
  }

  @Override
  public OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    try {
      handler.handle(Future.succeededFuture(new OAuth2TokenImpl(this, new JsonObject().put("access_token", token))));
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
    }
    return this;
  }

  @Override
  public OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<AccessToken>> handler) {
    try {
      // attempt to create a token object from the given string representation
      final AccessToken accessToken = new OAuth2TokenImpl(this, new JsonObject().put(tokenType, token));
      // if token is expired avoid going to the server
      if (accessToken.expired()) {
        handler.handle(Future.failedFuture("Expired token"));
        return this;
      }
      // perform the introspection
      accessToken.introspect(introspect -> {
        if (introspect.failed()) {
          handler.handle(Future.failedFuture(introspect.cause()));
          return;
        }
        // the access token object should have updated it's claims/authorities plus expiration, recheck
        if (accessToken.expired()) {
          handler.handle(Future.failedFuture("Expired token"));
          return;
        }
        // return self
        handler.handle(Future.succeededFuture(accessToken));
      });
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
    }
    return this;
  }

  @Override
  public String getScopeSeparator() {
    final String sep = config.getScopeSeparator();
    return sep == null ? " " : sep;
  }

  @Override
  public OAuth2FlowType getFlowType() {
    return flowType;
  }

  public OAuth2Flow getFlow() {
    return flow;
  }
}
