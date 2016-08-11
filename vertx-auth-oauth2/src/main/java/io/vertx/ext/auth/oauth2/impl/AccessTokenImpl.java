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
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.AccessToken;

import java.nio.charset.StandardCharsets;

/**
 * @author Paulo Lopes
 */
public class AccessTokenImpl extends AbstractUser implements AccessToken {

  private static final Logger log = LoggerFactory.getLogger(AccessTokenImpl.class);

  private static final JsonObject EMPTY_JSON = new JsonObject();
  private static final JsonArray EMPTY_ARRAY = new JsonArray();

  private OAuth2AuthProviderImpl provider;

  /**
   * The RAW token
   */
  private JsonObject token;

  /**
   * This json is build from the access_token, if present, assuming it is encoded as JWT
   */
  private JsonObject content;

  /**
   * Creates an AccessToken instance.
   */
  public AccessTokenImpl() {
    // required if the object is serialized, however this is probably not a good idea
    // because Tokens are supposed to be used in stateless environments
    log.info("You are probably serializing the OAuth2 User, OAuth2 tokens are supposed to be used in stateless servers!");
  }

  /**
   * Creates an AccessToken instance.
   * @param token - An object containing the token object returned from the OAuth2 server.
   */
  public AccessTokenImpl(OAuth2AuthProviderImpl provider, JsonObject token) {
    this.provider = provider;

    init(token);
  }

  private void init(JsonObject json) {
    if (json.containsKey("expires_in")) {
      json = json.copy();
      json.put("expires_at", System.currentTimeMillis() + 1000 * json.getLong("expires_in"));
    }

    this.token = json;

    // try to parse the access_token
    if (provider.getConfig().isJwtToken() && json.containsKey("access_token")) {
      content = provider.getVerifier().verify(json.getString("access_token"));
    }
  }

  /**
   * Check if the access token is expired or not.
   */
  @Override
  public boolean expired() {
    return token.containsKey("expires_at") && token.getLong("expires_at", 0L) < System.currentTimeMillis();
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

    OAuth2API.api(provider, HttpMethod.POST, provider.getConfig().getTokenPath(), params, res -> {
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

    final String tokenValue = token.getString(token_type);

    if (tokenValue != null) {

      JsonObject params = new JsonObject()
          .put("token", tokenValue)
          .put("token_type_hint", token_type);

      OAuth2API.api(provider, HttpMethod.POST, provider.getConfig().getRevocationPath(), params, res -> {
        if (res.succeeded()) {

          // invalidate ourselves
          token.remove(token_type);
          if ("access_token".equals(token_type)) {
            content = null;
          }

          callback.handle(Future.succeededFuture());
        } else {
          callback.handle(Future.failedFuture(res.cause()));
        }
      });
    } else {
      callback.handle(Future.failedFuture("Invalid token: " + token_type));
    }

    return this;
  }

  /**
   * Revoke refresh token and calls the logout endpoint
   *
   * @param callback - The callback function returning the results.
   */
  @Override
  public AccessTokenImpl logout(Handler<AsyncResult<Void>> callback) {

    JsonObject params = new JsonObject()
        .put("access_token", token.getString("access_token"))
        .put("refresh_token", token.getString("refresh_token"));

    OAuth2API.api(provider, HttpMethod.POST, provider.getConfig().getLogoutPath(), params, res -> {
      if (res.succeeded()) {

        // invalidate ourselves
        token = null;
        content = null;

        callback.handle(Future.succeededFuture());
      } else {
        callback.handle(Future.failedFuture(res.cause()));
      }
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
   * @param permission The role name specifier.
   * @param resultHandler `true` if this token has the specified role, otherwise `false`.
   */
  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {

    if (expired()) {
      resultHandler.handle(Future.failedFuture("Expired Token"));
      return;
    }

    if (provider.getConfig().isJwtToken()) {
      String[] parts = permission.split(":");

      if (parts.length == 1) {
        resultHandler.handle(Future.succeededFuture(hasApplicationRole(provider.getConfig().getClientID(), parts[0])));
        return ;
      }

      if ("realm".equals(parts[0])) {
        resultHandler.handle(Future.succeededFuture(hasRealmRole(parts[1])));
        return;
      }

      resultHandler.handle(Future.succeededFuture(hasApplicationRole(parts[0], parts[1])));
    } else {
      resultHandler.handle(Future.succeededFuture(false));
    }
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
    JsonObject appRoles = content
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
    return content
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
    this.provider = (OAuth2AuthProviderImpl) authProvider;
  }

  @Override
  public void touch() {
    //NOOP
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes = token.encode().getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);

    bytes = content.encode().getBytes(StandardCharsets.UTF_8);
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

    len = buffer.getInt(pos);
    pos += 4;
    bytes = buffer.getBytes(pos, pos + len);
    content = new JsonObject(new String(bytes, StandardCharsets.UTF_8));
    pos += len;

    return pos;
  }
}
