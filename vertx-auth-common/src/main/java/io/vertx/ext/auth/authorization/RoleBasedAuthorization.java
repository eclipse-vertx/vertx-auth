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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.impl.RoleBasedAuthorizationImpl;

/**
 * Represents a role. Note that this role can optionally be assigned to a
 * specific resource
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface RoleBasedAuthorization extends Authorization {

  static RoleBasedAuthorization create(String role) {
    return new RoleBasedAuthorizationImpl(role);
  }

  /**
   * returns the role
   *
   * @return
   */
  String getRole();

  /**
   * returns an optional resource that the role is assigned-on
   *
   * @return
   */
  String getResource();

  /**
   * sets an optional resource that the role is assigned-on
   *
   * @return
   */
  @Fluent
  RoleBasedAuthorization setResource(String resource);

}
