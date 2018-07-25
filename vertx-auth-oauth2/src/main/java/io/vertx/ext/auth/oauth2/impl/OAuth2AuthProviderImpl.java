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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.jwt.JWK;
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.impl.flow.*;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.fetch;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth {

  private final Vertx vertx;
  private final OAuth2ClientOptions config;
  private final JWT jwt = new JWT();

  private final OAuth2Flow flow;

  private OAuth2RBAC rbac;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2ClientOptions config) {
    this.vertx = vertx;
    this.config = config;

    if (config.getPubSecKeys() != null) {
      for (PubSecKeyOptions pubSecKey : config.getPubSecKeys()) {
        if (pubSecKey.isSymmetric()) {
          jwt.addJWK(new JWK(pubSecKey.getAlgorithm(), pubSecKey.getPublicKey()));
        } else {
          jwt.addJWK(new JWK(pubSecKey.getAlgorithm(), pubSecKey.isCertificate(), pubSecKey.getPublicKey(), pubSecKey.getSecretKey()));
        }
      }
    }

    switch (config.getFlow()) {
      case AUTH_CODE:
        flow = new AuthCodeImpl(this);
        break;
      case CLIENT:
        flow = new ClientImpl(this);
        break;
      case PASSWORD:
        flow = new PasswordImpl(this);
        break;
      case AUTH_JWT:
        flow = new AuthJWTImpl(this);
        break;
      default:
        throw new IllegalArgumentException("Unsupported oauth2 flow type: " + config.getFlow());
    }
  }

  @Override
  public OAuth2Auth loadJWK(Handler<AsyncResult<Void>> handler) {
    final JsonObject headers = new JsonObject();
    // specify preferred accepted content type
    headers.put("Accept", "application/json");

    fetch(
      vertx,
      config,
      HttpMethod.GET,
      config.getJwkPath(),
      headers,
      null,
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
            JsonArray keys = json.getJsonArray("keys");
            for (Object key : keys) {
              jwt.addJWK(new JWK((JsonObject) key));
            }

            handler.handle(Future.succeededFuture());
          }
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });

    return this;
  }

  @Override
  public OAuth2Auth rbacHandler(OAuth2RBAC rbac) {
    if (this.rbac != null) {
      throw new IllegalStateException("There is already a RBAC handler registered");
    }

    this.rbac = rbac;
    return this;
  }

  OAuth2RBAC getRBACHandler() {
    return rbac;
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
    // if the authInfo object already contains a token validate it to confirm that it
    // can be reused, otherwise, based on the configured flow, request a new token
    // from the authority provider

    if (
      // authInfo contains a token_type of Bearer
      authInfo.containsKey("token_type") && "Bearer".equalsIgnoreCase(authInfo.getString("token_type")) &&
      // authInfo contains a non null token
      authInfo.containsKey("access_token") && authInfo.getString("access_token") != null) {

      // this validation can be done in 2 different ways:
      // 1) the token is a JWT and in this case if the provider is OpenId Compliant the token can be verified locally
      // 2) the token is an opaque string and we need to introspect it

      // if the JWT library is working in unsecure mode, local validation is not to be trusted

      final AccessToken oauth2Token = new OAuth2TokenImpl(this, authInfo);

      // the token is not a JWT or there are no loaded keys to validate
      if (oauth2Token.accessToken() == null || jwt.isUnsecure()) {
        // the token is not in JWT format or this auth provider is not configured for secure JWTs
        // in this case we must rely on token introspection in order to know more about its state
        // attempt to create a token object from the given string representation

        // perform the introspection
        oauth2Token.introspect(introspect -> {
          if (introspect.failed()) {
            resultHandler.handle(Future.failedFuture(introspect.cause()));
            return;
          }
          // the access token object should have updated it's claims/authorities plus expiration, recheck
          if (oauth2Token.expired()) {
            resultHandler.handle(Future.failedFuture("Expired token"));
            return;
          }
          // return self
          resultHandler.handle(Future.succeededFuture(oauth2Token));
        });
      } else {
        // a valid JWT token should have the access token value decoded
        // the token might be valid, but expired
        if (oauth2Token.expired()) {
          resultHandler.handle(Future.failedFuture("Expired Token"));
        } else {
          resultHandler.handle(Future.succeededFuture(oauth2Token));
        }
      }

    } else {
      // the authInfo object does not contain a token, so rely on the
      // configured flow to retrieve a token for the user
      flow.getToken(authInfo, getToken -> {
        if (getToken.failed()) {
          resultHandler.handle(Future.failedFuture(getToken.cause()));
        } else {
          resultHandler.handle(Future.succeededFuture(getToken.result()));
        }
      });
    }
  }

  @Override
  public String authorizeURL(JsonObject params) {
    return flow.authorizeURL(params);
  }

  @Override
  @Deprecated
  public void getToken(JsonObject credentials, Handler<AsyncResult<AccessToken>> handler) {
    flow.getToken(credentials, handler);
  }

  @Override
  @Deprecated
  public OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    authenticate(new JsonObject().put("access_token", token).put("token_type", "Bearer"), auth -> {
      if (auth.succeeded()) {
        handler.handle(Future.succeededFuture((AccessToken) auth.result()));
      } else {
        handler.handle(Future.failedFuture(auth.cause()));
      }
    });
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
  @Deprecated
  public String getScopeSeparator() {
    final String sep = config.getScopeSeparator();
    return sep == null ? " " : sep;
  }

  @Override
  public OAuth2FlowType getFlowType() {
    return config.getFlow();
  }

  public OAuth2Flow getFlow() {
    return flow;
  }
}
