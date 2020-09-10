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
package io.vertx.ext.auth.webauthn.store;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;

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
public interface AuthenticatorStore {

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
   * @param name user unique name.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthenticatorStore getAuthenticatorsByUserName(String name, Handler<AsyncResult<List<Authenticator>>> handler) {
    handler.handle(Future.failedFuture("getAuthenticatorsByUserName not supported"));
    return this;
  }

  /**
   * Same as {@link #getAuthenticatorsByUserName(String, Handler)} but using a Future.
   */
  default Future<List<Authenticator>> getAuthenticatorsByUserName(String username) {
    Promise<List<Authenticator>> promise = Promise.promise();
    getAuthenticatorsByUserName(username, promise);
    return promise.future();
  }

  /**
   * Retrieves the user credentials from a backend given the user unique identifier.
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   *
   * @param id user unique rawId.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthenticatorStore getAuthenticatorsByCredId(String id, Handler<AsyncResult<List<Authenticator>>> handler) {
    handler.handle(Future.failedFuture("getAuthenticatorsByCredId not supported"));
    return this;
  }

  /**
   * Same as {@link #getAuthenticatorsByCredId(String, Handler)} but using a Future.
   */
  default Future<List<Authenticator>> getAuthenticatorsByCredId(String rawId) {
    Promise<List<Authenticator>> promise = Promise.promise();
    getAuthenticatorsByCredId(rawId, promise);
    return promise.future();
  }

  /**
   * Update the user credential.
   *
   * @param authenticator authenticator data to update.
   * @param upsert insert if not present.
   * @param handler the handler for the result callback.
   * @return fluent self.
   */
  @Fluent
  default AuthenticatorStore update(Authenticator authenticator, boolean upsert, Handler<AsyncResult<Void>> handler) {
    handler.handle(Future.failedFuture("update not supported"));
    return this;
  }

  /**
   * Same as {@link #update(Authenticator, boolean, Handler)} but using a Future.
   */
  default Future<Void> update(Authenticator authenticator, boolean upsert) {
    Promise<Void> promise = Promise.promise();
    update(authenticator, upsert, promise);
    return promise.future();
  }
}
