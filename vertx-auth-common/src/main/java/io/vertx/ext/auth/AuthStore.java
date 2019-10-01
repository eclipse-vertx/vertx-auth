/*
 * Copyright 2019 Red Hat, Inc.
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
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;

import java.util.List;

/**
 * Generic interface to fetch user related information from a server backend.
 *
 * All methods of this interface are optional.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface AuthStore {

  /**
   * Retrieves the user credentials from a backend given the user unique identifier.
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   *
   * @param id user unique identified.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthStore getUserCredentials(String id, Handler<AsyncResult<List<JsonObject>>> handler) {
    handler.handle(Future.failedFuture("getUserCredentials not supported"));
    return this;
  }

  /**
   * Same as {@link #getUserCredentials(String, Handler)} but using a Future.
   */
  default Future<List<JsonObject>> getUserCredentials(String id) {
    Promise<List<JsonObject>> promise = Promise.promise();
    getUserCredentials(id, promise);
    return promise.future();
  }

  /**
   * Update the user credential.
   *
   * @param id the unique user identifier.
   * @param data the data to update.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthStore updateUserCredential(String id, JsonObject data, Handler<AsyncResult<Void>> handler) {
    handler.handle(Future.failedFuture("updateUserCredentials not supported"));
    return this;
  }

  /**
   * Same as {@link #updateUserCredential(String, JsonObject, Handler)} but using a Future.
   */
  default Future<Void> updateUserCredential(String id, JsonObject data) {
    Promise<Void> promise = Promise.promise();
    updateUserCredential(id, data, promise);
    return promise.future();
  }

  /**
   * Get the user roles from the storage.
   *
   * @param id the unique user identifier.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthStore getUserRoles(String id, Handler<AsyncResult<List<String>>> handler) {
    handler.handle(Future.failedFuture("getUserRoles not supported"));
    return this;
  }

  /**
   * Same as {@link #getUserRoles(String, Handler)} but using a Future.
   */
  default Future<List<String>> getUserRoles(String id) {
    Promise<List<String>> promise = Promise.promise();
    getUserRoles(id, promise);
    return promise.future();
  }

  /**
   * Get the user permissions from the storage.
   *
   * @param id the unique user identifier.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthStore getUserPermissions(String id, Handler<AsyncResult<List<String>>> handler) {
    handler.handle(Future.failedFuture("getUserPermissions not supported"));
    return this;
  }

  /**
   * Same as {@link #getUserPermissions(String, Handler)} but using a Future.
   */
  default Future<List<String>> getUserPermissions(String id) {
    Promise<List<String>> promise = Promise.promise();
    getUserPermissions(id, promise);
    return promise.future();
  }
}
