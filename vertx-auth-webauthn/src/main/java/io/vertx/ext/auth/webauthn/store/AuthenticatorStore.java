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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;

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
   * Retrieves the {@link Authenticator}s from a backend given the incomplete {@link Authenticator}.
   *
   * The implementation must consider the following fields <strong>exclusively</strong>, while performing the lookup:
   * <ul>
   *   <li>{@link Authenticator#getUserName()}</li>
   *   <li>{@link Authenticator#getCredID()} ()}</li>
   * </ul>
   *
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   * To signal that a user is not allowed/present on the system, a failure should be returned, not {@code null}.
   *
   * @param authenticator the incomplete authenticator data to lookup.
   * @return Future async result with a list of authenticators.
   */
  default Future<List<Authenticator>> fetch(Authenticator authenticator) {
    return Future.failedFuture("AuthenticatorStore#fetch() not available");
  }

  /**
   * Store a given authenticator to some persistence storage.
   *
   * When an authenticator is already present, this method <strong>must</strong> at least update
   * {@link Authenticator#getCounter()}, and is not required to perform any other update.
   *
   * For new authenticators, the whole object data <strong>must</strong> be persisted.
   *
   * @param authenticator authenticator data to update.
   * @return Future async result with success status.
   */
  default Future<Void> store(Authenticator authenticator) {
    return Future.failedFuture("AuthenticatorStore#store() not available");
  }
}
