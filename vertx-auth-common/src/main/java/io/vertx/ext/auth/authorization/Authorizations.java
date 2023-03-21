/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 1
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static io.vertx.codegen.annotations.GenIgnore.PERMITTED_TYPE;

/**
 * Represents a cache map of authorizations per provider.
 *
 * Authorizations are immutable and can be shared between users.
 *
 * @author Stephane Bastian
 */
@VertxGen
public interface Authorizations {

  /**
   * Replaces the current authorizations with the given authorizations.
   * The map is expected to be immutable.
   *
   * @param authorizations the new map of authorizations.
   * @return fluent self.
   */
  @Fluent
  @GenIgnore
  Authorizations putAll(Map<String, Set<Authorization>> authorizations);

  /**
   * Replaces the current authorizations with the given authorizations for the given provider.
   *
   * @param providerId the provider.
   * @param authorizations the new map of authorizations. {@code null} is equivalent to remove all authorizations for
   *                      the given provider.
   * @return fluent self.
   */
  @Fluent
  Authorizations put(String providerId, Set<Authorization> authorizations);

  /**
   * Replaces the current authorizations with the given authorizations for the given provider.
   *
   * @param providerId the provider.
   * @param authorizations the new array of authorizations.
   * @return fluent self.
   */
  @Fluent
  @GenIgnore
  default Authorizations put(String providerId, Authorization... authorizations) {
    Set<Authorization> set = new HashSet<>();
    Collections.addAll(set, authorizations);
    return put(providerId, set);
  }

  /**
   * {@code true} if the authorizations contains at least one provider.
   */
  boolean isEmpty();

  /**
   * Clears the authorizations.
   */
  @Fluent
  Authorizations clear();

  /**
   * Logical check if the this object contains the given provider id
   * @param providerId the provider to search for.
   * @return {@code true} when the provider is present.
   */
  boolean contains(String providerId);

  /**
   * Verifies that the given authorization is present in the authorizations.
   * @param resolvedAuthorization the authorization to verify.
   * @return {@code true} if the authorization is present.
   */
  boolean verify(Authorization resolvedAuthorization);

  /**
   * Walk all the authorizations and call the consumer for each authorization.
   * @param consumer the consumer to call.
   */
  @Fluent
  @GenIgnore
  Authorizations forEach(BiConsumer<String, Authorization> consumer);

  /**
   * Walk all the authorizations for the given provider and call the consumer for each authorization.
   * @param consumer the consumer to call.
   */
  @Fluent
  @GenIgnore
  Authorizations forEach(String providerId, Consumer<Authorization> consumer);
}
