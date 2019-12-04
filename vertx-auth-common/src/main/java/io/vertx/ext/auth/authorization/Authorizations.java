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

import java.util.Set;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;

@VertxGen
public interface Authorizations {

  /**
   * Add a set of Authorizations by a given provider.
   *
   * @param providerId the provider identifier
   * @param authorizations the authorization set
   * @return the Authorizations to enable fluent use
   */
  @Fluent
  Authorizations add(String providerId, Set<Authorization> authorizations);

  /**
   * Add a single Authorization by a given provider.
   *
   * @param providerId the provider identifier
   * @param authorization the authorization to be added to the set
   * @return the Authorizations to enable fluent use
   */
  @Fluent
  Authorizations add(String providerId, Authorization authorization);

  /**
   * The Authorizations object will clear all loaded permissions for the given provider id.
   *
   * @param providerId the provider to be cleared
   * @return the Authorizations to enable fluent use
   */
  @Fluent
  Authorizations clear(String providerId);

  /**
   * The Authorizations object will clear all loaded permissions.
   *
   * @return the Authorizations to enable fluent use
   */
  @Fluent
  Authorizations clear();

  /**
   * Get the current set of authorizations for a given provider.
   *
   * @param providerId the provider id
   * @return the set of authorization
   */
  Set<Authorization> get(String providerId);

  /**
   * Returns the list of known provider ids
   * @return list of ids
   */
  Set<String> getProviderIds();
}
