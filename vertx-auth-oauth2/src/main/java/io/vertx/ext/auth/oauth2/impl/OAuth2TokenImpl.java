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
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

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
    refreshToken = decodeToken("refresh_token", trust);
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

    LOG.info("Refreshing AccessToken");

    final JsonObject headers = new JsonObject();
    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();

    JsonObject tmp = config.getHeaders();

    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form
      .put("grant_type", "refresh_token")
      .put("refresh_token", opaqueRefreshToken())
      // Salesforce does seem to require them
      .put("client_id", config.getClientID());

    if (config.getClientSecretParameterName() != null) {
      form.put(config.getClientSecretParameterName(), config.getClientSecret());
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider.getVertx(),
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
          handler.handle(Future.failedFuture("Cannot handle accessToken type: " + reply.headers().get("Content-Type")));
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
            OAuth2API.processNonStandardHeaders(json, reply, config.getScopeSeparator());
            LOG.debug("Got new AccessToken");
            init(json);
            handler.handle(Future.succeededFuture());
          }
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

    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();
    final String tokenValue = principal().getString(token_type);

    if (tokenValue != null) {


      final JsonObject headers = new JsonObject();

      JsonObject tmp = config.getHeaders();

      if (tmp != null) {
        headers.mergeIn(tmp);
      }

      final JsonObject form = new JsonObject();

      form
        .put("token", tokenValue)
        .put("token_type_hint", token_type);

      headers.put("Content-Type", "application/x-www-form-urlencoded");
      final Buffer payload = Buffer.buffer(stringify(form));
      // specify preferred accepted accessToken type
      headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

      OAuth2API.fetch(
        provider.getVertx(),
        config,
        HttpMethod.POST,
        config.getRevocationPath(),
        headers,
        payload,
        res -> {
          if (res.failed()) {
            handler.handle(Future.failedFuture(res.cause()));
            return;
          }

          final OAuth2Response reply = res.result();

          if (reply.body() == null) {
            handler.handle(Future.failedFuture("No Body"));
            return;
          }

          // invalidate ourselves
          principal().remove(token_type);
          init(principal());

          handler.handle(Future.succeededFuture());
        });
    } else {
      handler.handle(Future.failedFuture("Invalid token: " + token_type));
    }

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

    OAuth2API.fetch(
      provider.getVertx(),
      config,
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
    final JsonObject headers = new JsonObject();
    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();

    if (config.isUseBasicAuthorizationHeader()) {
      String basic = config.getClientID() + ":" + (config.getClientSecret() == null ? "" : config.getClientSecret());
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject()
      .put("token", principal().getString(tokenType))
      // optional param from RFC7662
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider.getVertx(),
      config,
      HttpMethod.POST,
      config.getIntrospectionPath(),
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
          handler.handle(Future.failedFuture("Cannot handle accessToken type: " + reply.headers().get("Content-Type")));
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
              processNonStandardHeaders(json, reply, config.getScopeSeparator());
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
                if (iat > now + config.getJWTOptions().getLeeway()) {
                  handler.handle(Future.failedFuture("Invalid token: iat > now"));
                  return;
                }
              }

              if (json.containsKey("exp")) {
                Long exp = json.getLong("exp");

                if (now - config.getJWTOptions().getLeeway() >= exp) {
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
          }
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
    final JsonObject headers = new JsonObject();
    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();
    final JsonObject extraParams = config.getUserInfoParameters();
    String path = config.getUserInfoPath();

    if (extraParams != null) {
      path += "?" + OAuth2API.stringify(extraParams);
    }

    headers.put("Authorization", "Bearer " + opaqueAccessToken());
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider.getVertx(),
      config,
      HttpMethod.GET,
      path,
      headers,
      null,
      fetch -> {
        if (fetch.failed()) {
          callback.handle(Future.failedFuture(fetch.cause()));
          return;
        }

        final OAuth2Response reply = fetch.result();
        // userInfo is expected to be an object
        JsonObject userInfo;

        if (reply.is("application/json")) {
          try {
            // userInfo is expected to be an object
            userInfo = reply.jsonObject();
          } catch (RuntimeException e) {
            callback.handle(Future.failedFuture(e));
            return;
          }
        } else if (reply.is("application/x-www-form-urlencoded") || reply.is("text/plain")) {
          try {
            // attempt to convert url encoded string to json
            userInfo = OAuth2API.queryToJSON(reply.body().toString());
          } catch (RuntimeException | UnsupportedEncodingException e) {
            callback.handle(Future.failedFuture(e));
            return;
          }
        } else {
          callback.handle(Future.failedFuture("Cannot handle Content-Type: " + reply.headers().get("Content-Type")));
          return;
        }

        OAuth2API.processNonStandardHeaders(principal(), reply, config.getScopeSeparator());
        // re-init to reparse the authorities
        init(principal());
        callback.handle(Future.succeededFuture(userInfo));
      });
    return this;
  }

  @Override
  public AccessToken fetch(HttpMethod method, String resource, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback) {
    final OAuth2AuthProviderImpl provider = getProvider();
    final OAuth2ClientOptions config = provider.getConfig();

    if (headers == null) {
      headers = new JsonObject();
    }

    // add the access token
    headers.put("Authorization", "Bearer " + opaqueAccessToken());

    OAuth2API.fetch(
      provider.getVertx(),
      config,
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
