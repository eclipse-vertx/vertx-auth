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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.regex.Pattern;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * @author Paulo Lopes
 */
public class OAuth2TokenImpl extends AbstractUser implements AccessToken {

  private static final Charset UTF8 = StandardCharsets.UTF_8;

  private static final JsonObject EMPTY_JSON = new JsonObject();
  private static final JsonArray EMPTY_ARRAY = new JsonArray();

  private OAuth2AuthProviderImpl provider;
  private boolean trustJWT = false;

  /**
   * The RAW token
   */
  private JsonObject token;

  /**
   * This json's are build from the access_token and id_token, if present, assuming it is encoded as JWT
   */
  private JsonObject accessToken;
  private JsonObject refreshToken;
  private JsonObject idToken;

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
  public OAuth2TokenImpl(OAuth2AuthProviderImpl provider, JsonObject token) {
    this.provider = provider;
    this.token = token;

    init();
  }

  private JsonObject decodeToken(String opaque) {
    if (opaque == null) {
      return null;
    }

    // if it is trusted we can attempt to parse anyway
    if (trustJWT) {
      String[] segments = opaque.split("\\.");
      if (segments.length == 2 || segments.length == 3) {
        // All segment should be base64
        String payloadSeg = segments[1];
        // base64 decode and parse JSON
        return new JsonObject(new String(Base64.getUrlDecoder().decode(payloadSeg), UTF8));
      }
    } else {
      if (!provider.getJWT().isUnsecure()) {
        return provider.getJWT().decode(opaque);
      }
    }

    throw new RuntimeException("Cannot decode: " + opaque);
  }

  private void init() {
    if (token.containsKey("expires_in")) {
      Long expiresIn;
      try {
        expiresIn = token.getLong("expires_in");
      } catch (ClassCastException e) {
        // for some reason someone decided to send a number as a String...
        expiresIn = Long.valueOf(token.getString("expires_in"));
      }
      token.put("expires_at", System.currentTimeMillis() + 1000 * expiresIn);
    }

    // attempt to decode tokens
    if (provider.getConfig().isOpenIdConnect()) {
      accessToken = decodeToken(token.getString("access_token"));
      refreshToken = decodeToken(token.getString("refresh_token"));
      idToken = decodeToken(token.getString("id_token"));
    }
    // the permission cache needs to be clear
    clearCache();
    // rebuild cache
    String scope = token.getString("scope");
    // avoid the case when scope is the literal "null" value.
    if (scope != null) {
      Collections.addAll(cachedPermissions, scope.split(Pattern.quote(provider.getScopeSeparator())));
    }
  }

  @Override
  public AccessToken setTrustJWT(boolean trust) {
    this.trustJWT = trust;
    // refresh the tokens
    accessToken = decodeToken(token.getString("access_token"));
    refreshToken = decodeToken(token.getString("refresh_token"));
    idToken = decodeToken(token.getString("id_token"));

    return this;
  }

  @Override
  public String opaqueAccessToken() {
    return token.getString("access_token");
  }

  @Override
  public String opaqueRefreshToken() {
    return token.getString("refresh_token");
  }

  @Override
  public String opaqueIdToken() {
    return token.getString("id_token");
  }

  @Override
  public String tokenType() {
    return token.getString("token_type");
  }

  @Override
  public JsonObject accessToken() {
    if (accessToken != null) {
      return accessToken.copy();
    }
    return null;
  }

  @Override
  public JsonObject refreshToken() {
    if (refreshToken != null) {
      return refreshToken.copy();
    }
    return null;
  }

  @Override
  public JsonObject idToken() {
    if (idToken != null) {
      return idToken.copy();
    }
    return null;
  }

  /**
   * Check if the access token is expired or not.
   */
  @Override
  public boolean expired() {

    long now = System.currentTimeMillis();

    // expires_at is a computed field always in millis
    if (token.containsKey("expires_at") && token.getLong("expires_at", 0L) < now) {
      return true;
    }

    // delegate to the JWT lib
    return provider.getJWT().isExpired(accessToken, provider.getConfig().getJWTOptions());
  }

  /**
   * Refresh the access token
   *
   * @param handler - The callback function returning the results.
   */
  @Override
  public OAuth2TokenImpl refresh(Handler<AsyncResult<Void>> handler) {

    final JsonObject headers = new JsonObject();

    JsonObject tmp = provider.getConfig().getHeaders();

    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form
      .put("grant_type", "refresh_token")
      .put("refresh_token", opaqueRefreshToken())
      // Salesforce does seem to require them
      .put("client_id", provider.getConfig().getClientID());

    if (provider.getConfig().getClientSecretParameterName() != null) {
      form.put(provider.getConfig().getClientSecretParameterName(), provider.getConfig().getClientSecret());
    }

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider,
      HttpMethod.POST,
      provider.getConfig().getTokenPath(),
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
            OAuth2API.processNonStandardHeaders(json, reply, provider.getConfig().getScopeSeparator());
            token = json;
            init();
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

    final String tokenValue = token.getString(token_type);

    if (tokenValue != null) {


      final JsonObject headers = new JsonObject();

      JsonObject tmp = provider.getConfig().getHeaders();

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
        provider,
        HttpMethod.POST,
        provider.getConfig().getRevocationPath(),
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
          token.remove(token_type);
          if ("access_token".equals(token_type)) {
            accessToken = null;
          }

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

    final JsonObject headers = new JsonObject();

    headers.put("Authorization", "Bearer " + opaqueAccessToken());

    JsonObject tmp = provider.getConfig().getHeaders();

    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject();

    form.put("client_id", provider.getConfig().getClientID());

    if (provider.getConfig().getClientSecretParameterName() != null) {
      form.put(provider.getConfig().getClientSecretParameterName(), provider.getConfig().getClientSecret());
    }

    form.put("refresh_token", token.getString("refresh_token"));

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider,
      HttpMethod.POST,
      provider.getConfig().getLogoutPath(),
      headers,
      payload,
      res -> {
        if (res.succeeded()) {
          // invalidate ourselves
          token = null;
          accessToken = null;

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
    final OAuth2ClientOptions config = provider.getConfig();

    if (config.isUseBasicAuthorizationHeader()) {
      String basic = config.getClientID() + ":" + config.getClientSecret();
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(basic.getBytes()));
    }

    JsonObject tmp = config.getHeaders();
    if (tmp != null) {
      headers.mergeIn(tmp);
    }

    final JsonObject form = new JsonObject()
      .put("token", token.getString(tokenType))
      // optional param from RFC7662
      .put("token_type_hint", tokenType);

    headers.put("Content-Type", "application/x-www-form-urlencoded");
    final Buffer payload = Buffer.buffer(stringify(form));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider,
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

            // validate client id
            if (json.containsKey("client_id") && !json.getString("client_id", "").equals(config.getClientID())) {
              handler.handle(Future.failedFuture("Wrong client_id"));
              return;
            }

            // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations do not return this)
            if (json.containsKey("active") && !json.getBoolean("active", false)) {
              handler.handle(Future.failedFuture("Inactive Token"));
              return;
            }

            // validate client id
            if (json.containsKey("client_id") && !json.getString("client_id", "").equals(provider.getConfig().getClientID())) {
              handler.handle(Future.failedFuture("Wrong client_id"));
              return;
            }

            try {
              processNonStandardHeaders(json, reply, config.getScopeSeparator());
              // reset the access token
              token.mergeIn(json);
              init();

              if (expired()) {
                handler.handle(Future.failedFuture("Expired token"));
                return;
              }

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
    final JsonObject extraParams = provider.getConfig().getUserInfoParameters();
    String path = provider.getConfig().getUserInfoPath();

    if (extraParams != null) {
      path += "?" + OAuth2API.stringify(extraParams);
    }

    headers.put("Authorization", "Bearer " + token.getString("access_token"));
    // specify preferred accepted accessToken type
    headers.put("Accept", "application/json,application/x-www-form-urlencoded;q=0.9");

    OAuth2API.fetch(
      provider,
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

        OAuth2API.processNonStandardHeaders(token, reply, provider.getConfig().getScopeSeparator());
        // re-init to reparse the authorities
        init();
        callback.handle(Future.succeededFuture(userInfo));
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

    OAuth2API.fetch(provider, method, resource, headers, payload, fetch -> {
      if (fetch.failed()) {
        callback.handle(Future.failedFuture(fetch.cause()));
        return;
      }

      callback.handle(Future.succeededFuture(fetch.result()));
    });
    return this;
  }

  /**
   * Determine if this token has an associated role.
   * <p>
   * This method is only functional if the token is constructed
   * with a `clientId` parameter.
   * <p>
   * The parameter matches a role specification using the following rules:
   * <p>
   * - If the name contains no colons, then the name is taken as the entire
   * name of a role within the current application, as specified via
   * `clientId`.
   * - If the name starts with the literal `realm:`, the subsequent portion
   * is taken as the name of a _realm-level_ role.
   * - Otherwise, the name is split at the colon, with the first portion being
   * taken as the name of an arbitrary application, and the subsequent portion
   * as the name of a role with that app.
   *
   * @param permission    The role name specifier.
   * @param resultHandler `true` if this token has the specified role, otherwise `false`.
   */
  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {

    if (expired()) {
      resultHandler.handle(Future.failedFuture("Expired Token"));
      return;
    }

    String[] parts = permission.split(":");

    if (parts.length == 1) {
      resultHandler.handle(Future.succeededFuture(hasApplicationRole(provider.getConfig().getClientID(), parts[0])));
      return;
    }

    if ("realm".equals(parts[0])) {
      resultHandler.handle(Future.succeededFuture(hasRealmRole(parts[1])));
      return;
    }

    resultHandler.handle(Future.succeededFuture(hasApplicationRole(parts[0], parts[1])));
  }

  /**
   * Determine if this token has an associated specific application role.
   * <p>
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for any given application.
   *
   * @param appName  The identifier of the application to test.
   * @param roleName The name of the role within that application to test.
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  private boolean hasApplicationRole(String appName, String roleName) {
    if (accessToken == null) {
      return false;
    }

    JsonObject appRoles = accessToken
      .getJsonObject("resource_access", EMPTY_JSON)
      .getJsonObject(appName);

    if (appRoles == null) {
      return false;
    }

    return appRoles
      .getJsonArray("roles", EMPTY_ARRAY)
      .contains(roleName);
  }

  /**
   * Determine if this token has an associated specific realm-level role.
   * <p>
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for the realm.
   *
   * @param roleName The name of the role within that application to test.
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  private boolean hasRealmRole(String roleName) {
    if (accessToken == null) {
      return false;
    }

    return accessToken
      .getJsonObject("realm_access", EMPTY_JSON)
      .getJsonArray("roles", EMPTY_ARRAY)
      .contains(roleName);
  }

  @Override
  public JsonObject principal() {
    return token;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    provider = (OAuth2AuthProviderImpl) authProvider;
    // re-attempt to decode tokens
    init();
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
    // force reparse of the token
    if (provider != null) {
      init();
    }

    return pos;
  }
}
