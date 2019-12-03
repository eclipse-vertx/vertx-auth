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

import java.util.Set;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;

/**
 * The role of an AuthorizationProvider is to return a set of Authorization.
 * Note that each AuthorizationProvider must provide its own unique Id
 *
 * @author stephane bastian
 *
 */
@VertxGen(concrete = false)
public interface AuthorizationProvider {

  /**
   * returns the id of the authorization provider
   *
   * @return
   */
  String getId();

  /**
   * Returns the set of authorizations of the specified user
   *
   * @param user
   * @param handler
   */
  void getAuthorizations(User user, Handler<AsyncResult<Set<Authorization>>> handler);

}
