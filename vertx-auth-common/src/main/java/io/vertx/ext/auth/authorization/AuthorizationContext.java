/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.MultiMap;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.impl.AuthorizationContextImpl;

/**
 * The AuthorizationContext contains properties that can be used to match
 * authorizations.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface AuthorizationContext {

  /**
   * Factory for Authorization Context
   *
   * @param user a user
   * @return a AuthorizationContext instance
   */
  static AuthorizationContext create(User user) {
    return new AuthorizationContextImpl(user);
  }

  /**
   * Get the authenticated user
   *
   * @return the user
   */
  User user();

  /**
   * @return a Multimap containing variable names and values that can be resolved
   * at runtime by {@link Authorization}Authorizations
   */
  MultiMap variables();

}
