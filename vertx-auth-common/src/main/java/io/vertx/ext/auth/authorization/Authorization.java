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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.User;

import static io.vertx.codegen.annotations.GenIgnore.PERMITTED_TYPE;

/**
 * Interface representing any kind of authorization such as:
 * <ul>
 *   <li>Role based authorization
 *   <li>Permission based authorization
 *   <li>Logical authorization (AND, OR, NOT)
 *   <li>Time based authorization (ie: allow access the last 5 days of the month, from 8am till 10am, etc.)
 *   <li>Context based authorization (ie: allow access if the ip address is 'xxx.xxx.xxx.xxx')
 *   <li>Custom based authorization (ie: based on a script or hard-coded code specific to an application)
 *   <li>etc.
 * </ul>
 * The following implementations are provided out of the box:
 * <ul>
 *   <li>{@link AndAuthorization}
 *   <li>{@link NotAuthorization}
 *   <li>{@link OrAuthorization}
 *   <li>{@link PermissionBasedAuthorization}
 *   <li>{@link RoleBasedAuthorization}
 *   <li>{@link WildcardPermissionBasedAuthorization}
 * </ul>
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@VertxGen
public interface Authorization {

  /**
   * this methods verifies whether or not the authorization match the specified
   * context.
   *
   * @param context the context.
   * @return true if there's a match.
   */
  boolean match(AuthorizationContext context);

  /**
   * this methods verifies whether or not the authorization match the specified
   * user. Internally a basic context is created with the user and the method
   * delegates to {@link #match(AuthorizationContext)}
   *
   * @param user the user.
   * @return true if there's a match
   */
  @GenIgnore(PERMITTED_TYPE)
  default boolean match(User user) {
    return match(AuthorizationContext.create(user));
  }

  /**
   * this method verifies whether or not the authorization implies the specified
   * authorization.
   * </br>Note that it doesn't always mean an exact match. For instance,
   * in the case of a {@link WildcardPermissionBasedAuthorization}, this method
   * may return true even if the permissions are different
   * </br>WildcardPermissionBasedAuthorization.create('*').verify(WildcardPermissionBasedAuthorization.create('anypermission'))
   * would return true
   *
   * @param authorization the authorization.
   * @return true if implies the argument.
   */
  boolean verify(Authorization authorization);
}
