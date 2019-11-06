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
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.PermissionBasedAuthorizationImpl;

/**
 * Represents a permission Note that the permission can optionally be assigned
 * to a specific resource
 * 
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface PermissionBasedAuthorization extends Authorization {

  static PermissionBasedAuthorization create(String permission) {
    return new PermissionBasedAuthorizationImpl(permission);
  }

  /**
   * returns the value of the permission
   * 
   * @return
   */
  String getPermission();

  /**
   * returns an optional resource that the permission is assigned-on
   * 
   * @return
   */
  String getResource();

  /**
   * sets an optional resource that the permission is assigned-on
   * 
   * @return
   */
  @Fluent
  PermissionBasedAuthorization setResource(String resource);

}
