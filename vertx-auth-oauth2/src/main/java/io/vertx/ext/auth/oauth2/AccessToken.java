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
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.CacheReturn;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;

/**
 * AccessToken extension to the User interface
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface AccessToken extends User {

  /**
   * Check if the access token is expired or not.
   */
  boolean expired();

  /**
   * The Access Token if present parsed as a JsonObject
   * @return JSON
   */
  @CacheReturn
  JsonObject accessToken();

  /**
   * The Id Token if present parsed as a JsonObject
   * @return JSON
   */
  @CacheReturn
  JsonObject idToken();

  /**
   * The RAW String if available for the Access Token
   * @return String
   */
  String opaqueAccessToken();

  /**
   * The RAW String if available for the Refresh Token
   * @return String
   */
  String opaqueRefreshToken();

  /**
   * The RAW String if available for the Id Token
   * @return String
   */
  String opaqueIdToken();

  String tokenType();

  @Fluent
  AccessToken setTrustJWT(boolean trust);

  /**
   * Refresh the access token
   *
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken refresh(Handler<AsyncResult<Void>> callback);

  /**
   * Refresh the access token
   *
   * @return future returning the results.
   */
  default Future<Void> refresh() {
    Promise<Void> promise = Promise.promise();
    refresh(promise);
    return promise.future();
  }

  /**
   * Revoke access or refresh token
   *
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken revoke(String token_type, Handler<AsyncResult<Void>> callback);

  /**
   * Revoke access or refresh token
   *
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @return future returning the results.
   */
  default Future<Void> revoke(String token_type) {
    Promise<Void> promise = Promise.promise();
    revoke(token_type, promise);
    return promise.future();
  }

  /**
   * Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   * available on all providers.
   *
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken logout(Handler<AsyncResult<Void>> callback);

  /**
   * Revoke refresh token and calls the logout endpoint. This is a openid-connect extension and might not be
   * available on all providers.
   *
   * @return future returning the results.
   */
  default Future<Void> logout() {
    Promise<Void> promise = Promise.promise();
    logout(promise);
    return promise.future();
  }

  /**
   * Introspect access token. This is an OAuth2 extension that allow to verify if an access token is still valid.
   *
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken introspect(Handler<AsyncResult<Void>> callback);

  /**
   * Introspect access token. This is an OAuth2 extension that allow to verify if an access token is still valid.
   *
   * @return future returning the results.
   */
  default Future<Void> introspect() {
    Promise<Void> promise = Promise.promise();
    introspect(promise);
    return promise.future();
  }

  /**
   * Introspect access token. This is an OAuth2 extension that allow to verify if an access token is still valid.
   *
   * @param tokenType - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken introspect(String tokenType, Handler<AsyncResult<Void>> callback);

  /**
   * Introspect access token. This is an OAuth2 extension that allow to verify if an access token is still valid.
   *
   * @param tokenType - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @return future returning the results.
   */
  default Future<Void> introspect(String tokenType) {
    Promise<Void> promise = Promise.promise();
    introspect(tokenType, promise);
    return promise.future();
  }

  /**
   * Load the user info as per OIDC spec.
   *
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken userInfo(Handler<AsyncResult<JsonObject>> callback);

  /**
   * Load the user info as per OIDC spec.
   *
   * @return future returning the results.
   */
  default Future<JsonObject> userInfo() {
    Promise<JsonObject> promise = Promise.promise();
    userInfo(promise);
    return promise.future();
  }

  /**
   * Fetches a JSON resource using this Access Token.
   *
   * @param resource - the resource to fetch.
   * @param callback - The callback function returning the results.
   */
  @Fluent
  default AccessToken fetch(String resource, Handler<AsyncResult<OAuth2Response>> callback) {
    return fetch(HttpMethod.GET, resource, null, null, callback);
  }

  /**
   * Fetches a JSON resource using this Access Token.
   *
   * @param resource - the resource to fetch.
   * @return future returning the results.
   */
  default Future<OAuth2Response> fetch(String resource) {
    Promise<OAuth2Response> promise = Promise.promise();
    fetch(resource, promise);
    return promise.future();
  }

  /**
   * Fetches a JSON resource using this Access Token.
   *
   * @param method - the HTTP method to user.
   * @param resource - the resource to fetch.
   * @param headers - extra headers to pass to the request.
   * @param payload - payload to send to the server.
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken fetch(HttpMethod method, String resource, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback);

  /**
   * Fetches a JSON resource using this Access Token.
   *
   * @param method - the HTTP method to user.
   * @param resource - the resource to fetch.
   * @param headers - extra headers to pass to the request.
   * @param payload - payload to send to the server.
   * @return future returning the results.
   */
  default Future<OAuth2Response> fetch(HttpMethod method, String resource, JsonObject headers, Buffer payload) {
    Promise<OAuth2Response> promise = Promise.promise();
    fetch(method, resource, headers, payload, promise);
    return promise.future();
  }
}
