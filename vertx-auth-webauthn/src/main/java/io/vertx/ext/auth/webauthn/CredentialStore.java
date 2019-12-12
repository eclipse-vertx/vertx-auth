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
package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;

import java.util.List;
import java.util.UUID;

/**
 * Generic interface to fetch user related information from a server backend.
 *
 * All methods of this interface are optional.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface CredentialStore {

  /**
   * Generates a unique ID that doesn't contain any user identifiable information. By default it generates a random UUID.
   * Although this is will work for most cases a better implementation that prevents collisions of IDs should be
   * preferred.
   *
   * @return a new unique ID as a string
   */
  default String generateId() {
    return UUID.randomUUID().toString();
  }

  /**
   * Retrieves the user credentials from a backend given the user unique identifier.
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   *
   * @param username user unique name.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default CredentialStore getUserCredentialsByName(String username, Handler<AsyncResult<List<JsonObject>>> handler) {
    handler.handle(Future.failedFuture("getUserCredentials not supported"));
    return this;
  }

  /**
   * Same as {@link #getUserCredentialsByName(String, Handler)} but using a Future.
   */
  default Future<List<JsonObject>> getUserCredentialsByName(String username) {
    Promise<List<JsonObject>> promise = Promise.promise();
    getUserCredentialsByName(username, promise);
    return promise.future();
  }

  /**
   * Retrieves the user credentials from a backend given the user unique identifier.
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   *
   * @param rawId user unique rawId.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default CredentialStore getUserCredentialsById(String rawId, Handler<AsyncResult<List<JsonObject>>> handler) {
    handler.handle(Future.failedFuture("getUserCredentials not supported"));
    return this;
  }

  /**
   * Same as {@link #getUserCredentialsById(String, Handler)} but using a Future.
   */
  default Future<List<JsonObject>> getUserCredentialsById(String rawId) {
    Promise<List<JsonObject>> promise = Promise.promise();
    getUserCredentialsById(rawId, promise);
    return promise.future();
  }

  /**
   * Update the user credential.
   *
   * @param id the unique user identifier.
   * @param data the data to update.
   * @param upsert insert if not present.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default CredentialStore updateUserCredential(String id, JsonObject data, boolean upsert, Handler<AsyncResult<Void>> handler) {
    handler.handle(Future.failedFuture("updateUserCredentials not supported"));
    return this;
  }

  /**
   * Same as {@link #updateUserCredential(String, JsonObject, boolean, Handler)} but using a Future.
   */
  default Future<Void> updateUserCredential(String id, JsonObject data, boolean upsert) {
    Promise<Void> promise = Promise.promise();
    updateUserCredential(id, data, upsert, promise);
    return promise.future();
  }
}
