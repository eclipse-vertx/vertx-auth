/*
 * Copyright 2014 Red Hat, Inc.
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

package io.vertx.ext.auth.spi;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

/**
 * This interface is implemented by auth providers which provide the actual auth functionality -
 * e.g. we have a implementation which uses Apache Shiro.
 * <p>
 * If you wish to use the auth service with other providers, implement this interface for your provider.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public interface AuthProvider {

  /**
   * The auth service will call this when the service is created
   *
   * @param config - the config to pass to your implementation
   */
  void init(JsonObject config);

  /**
   * Handle the actual login
   *
   * @param credentials  the credentials - this can contain anything your provider expects
   * @param resultHandler - this must return a failed result if login fails and it must return a succeeded result which
   *                      contains the `principal` object representing the logged in entity.
   */
  void login(JsonObject credentials, Handler<AsyncResult<Object>> resultHandler);

  /**
   * Handle whether a principal has a role
   *
   * @param principal  the principal object that you returned from {@link #login}.
   * @param role  the role
   * @param resultHandler  this must return a failure if the check could not be performed - e.g. the principal is not
   *                       known. Otherwise it must return a succeeded result which contains a boolean `true` if the
   *                       principal has the role, or `false` if they do not have the role.
   */
  void hasRole(Object principal, String role, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Handle whether a principal has a permission
   *
   * @param principal  the principal object that you returned from {@link #login}.
   * @param permission  the permission
   * @param resultHandler  this must return a failure if the check could not be performed - e.g. the principal is not
   *                       known. Otherwise it must return a succeeded result which contains a boolean `true` if the
   *                       principal has the permission, or `false` if they do not have the permission.
   */
  void hasPermission(Object principal, String permission, Handler<AsyncResult<Boolean>> resultHandler);

}
