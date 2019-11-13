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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
public class OAuth2TokenImpl extends OAuth2UserImpl {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2TokenImpl.class);

  /**
   * Creates an AccessToken instance.
   */
  public OAuth2TokenImpl() {
  }

  /**
   * Creates an AccessToken instance.
   *
   * @param token - An object containing the token object returned from the OAuth2 server.
   */
  public OAuth2TokenImpl(OAuth2Auth provider, JsonObject token) {
    super(provider, token);
  }

  @Override
  public AccessToken setTrustJWT(boolean trust) {
    // refresh the tokens
    accessToken = decodeToken("access_token", trust);
    idToken = decodeToken("id_token", trust);

    return this;
  }

  @Override
  public String tokenType() {
    return principal().getString("token_type");
  }

  /**
   * Refresh the access token
   *
   * @param handler - The callback function returning the results.
   */
  @Override
  public OAuth2TokenImpl refresh(Handler<AsyncResult<Void>> handler) {

    LOG.debug("Refreshing AccessToken");

    getProvider()
      .api()
      .token("refresh_token", new JsonObject().put("refresh_token", opaqueRefreshToken()), token -> {
        if (token.failed()) {
          handler.handle(Future.failedFuture(token.cause()));
          return;
        }

        try {
          init(token.result());
          handler.handle(Future.succeededFuture());
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });

    return this;
  }

  /**
   * Revoke access or refresh token
   *
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param handler    - The callback function returning the results.
   */
  @Override
  public OAuth2TokenImpl revoke(String token_type, Handler<AsyncResult<Void>> handler) {
    getProvider()
      .api()
      .tokenRevocation(token_type, principal().getString(token_type), res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        try {
          // invalidate ourselves
          principal().remove(token_type);
          init(principal());

          handler.handle(Future.succeededFuture());
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });

    return this;
  }

  /**
   * Revoke refresh token and calls the logout endpoint
   *
   * @param callback - The callback function returning the results.
   */
  @Override
  public OAuth2TokenImpl logout(Handler<AsyncResult<Void>> callback) {

    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();
    final JsonObject headers = new JsonObject();

    headers.put("Authorization", "Bearer " + opaqueAccessToken());

    JsonObject tmp = config.getHeaders();

    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form.put("client_id", config.getClientID());

    if (config.getClientSecretParameterName() != null && config.getClientSecret() != null) {
      form.put(config.getClientSecretParameterName(), config.getClientSecret());
    }

    final String refreshToken = opaqueRefreshToken();
    if (refreshToken != null) {
      form.put("refresh_token", opaqueRefreshToken());
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    getProvider()
      .api()
      .fetch(
        HttpMethod.POST,
        config.getLogoutPath(),
        headers,
        payload,
        res -> {
          if (res.succeeded()) {
            // invalidate ourselves
            init(null);
            callback.handle(Future.succeededFuture());
          } else {
            callback.handle(Future.failedFuture(res.cause()));
          }
        });

    return this;
  }

  @Override
  public AccessToken introspect(String tokenType, Handler<AsyncResult<Void>> handler) {

    getProvider()
      .api()
      .tokenIntrospection(tokenType, principal().getString(tokenType), res -> {
        if (res.failed()) {
          handler.handle(Future.failedFuture(res.cause()));
          return;
        }

        final JsonObject json = res.result();

        // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations do not return this)
        if (json.containsKey("active") && !json.getBoolean("active", false)) {
          handler.handle(Future.failedFuture("Inactive Token"));
          return;
        }
        // OPTIONALS

        if (json.containsKey("scope") && json.getString("scope") != null) {
          // A JSON string containing a space-separated list of scopes associated with this token
          principal().put("scope", json.getString("scope"));
        }

        // validate client id
        if (json.containsKey("client_id")) {
          if (principal().containsKey("client_id")) {
            if (!json.getString("client_id", "").equals(principal().getString("client_id"))) {
              // Client identifier for the OAuth 2.0 client that requested this token.
              handler.handle(Future.failedFuture("Wrong client_id"));
              return;
            }
          } else {
            principal().put("client_id", json.getString("client_id"));
          }
        }

        if (json.containsKey("username")) {
          // Human-readable identifier for the resource owner who authorized this token.
          principal().put("username", json.getString("username"));
        }

        // validate token type
        if (json.containsKey("token_type")) {
          if (principal().containsKey("token_type")) {
            if (!json.getString("token_type", "").equalsIgnoreCase(principal().getString("token_type"))) {
              // Client identifier for the OAuth 2.0 client that requested this token.
              handler.handle(Future.failedFuture("Wrong token_type"));
              return;
            }
          } else {
            principal().put("token_type", json.getString("token_type"));
          }
        }

        try {
          // reset the access token
          if (json.containsKey("expires_in")) {
            // reset the expires in value and reset the pre calculated value
            principal()
              .put("expires_in", json.getValue("expires_in"))
              .remove("expires_at");
          }

          // All dates in JWT are of type NumericDate
          // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
          // the specified UTC date/time, ignoring leap seconds
          final long now = (System.currentTimeMillis() / 1000);

          if (json.containsKey("iat")) {
            Long iat = json.getLong("iat");
            // issue at must be in the past
            if (iat > now + getProvider().getConfig().getJWTOptions().getLeeway()) {
              handler.handle(Future.failedFuture("Invalid token: iat > now"));
              return;
            }
          }

          if (json.containsKey("exp")) {
            Long exp = json.getLong("exp");

            if (now - getProvider().getConfig().getJWTOptions().getLeeway() >= exp) {
              handler.handle(Future.failedFuture("Invalid token: exp <= now"));
              return;
            }

            // reset the expires in value and reset the pre calculated value
            principal()
              .put("expires_in", exp - now)
              .remove("expires_at");
          }

          // force a init
          init(principal());

          handler.handle(Future.succeededFuture());
        } catch (RuntimeException e) {
          handler.handle(Future.failedFuture(e));
        }
      });

    return this;
  }

  @Override
  public AccessToken introspect(Handler<AsyncResult<Void>> handler) {
    return introspect("access_token", handler);
  }

  @Override
  public AccessToken userInfo(Handler<AsyncResult<JsonObject>> callback) {

    getProvider()
      .api()
      .userInfo(opaqueAccessToken(), res -> {
        if (res.failed()) {
          callback.handle(Future.failedFuture(res.cause()));
          return;
        }

        final JsonObject userInfo = res.result();

        try {
          // re-init to reparse the authorities
          init(principal());
          callback.handle(Future.succeededFuture(userInfo));
        } catch (RuntimeException e) {
          callback.handle(Future.failedFuture(e));
        }
      });

    return this;
  }

  @Override
  public AccessToken fetch(HttpMethod method, String resource, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback) {
    if (headers == null) {
      headers = new JsonObject();
    }

    // add the access token
    headers.put("Authorization", "Bearer " + opaqueAccessToken());

    getProvider()
      .api()
      .fetch(
        method,
        resource,
        headers,
        payload,
        fetch -> {
          if (fetch.failed()) {
            callback.handle(Future.failedFuture(fetch.cause()));
            return;
          }

          callback.handle(Future.succeededFuture(fetch.result()));
        });
    return this;
  }
}
