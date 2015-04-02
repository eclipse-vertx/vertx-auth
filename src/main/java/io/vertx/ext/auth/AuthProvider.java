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

package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
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
@VertxGen
public interface AuthProvider {

  /**
   * Handle the actual login
   *
   * @param principal  represents the unique id (e.g. username) of the user being logged in
   * @param credentials  the credentials - this can contain anything your provider expects, e.g. password
   * @param resultHandler - this must return a failed result if login fails and it must return a succeeded result if the
   *                      login succeeds
   */
  void login(JsonObject principal, JsonObject credentials, Handler<AsyncResult<Void>> resultHandler);

  /**
   * Handle whether a principal has a role
   *
   * @param principal  represents the unique id (e.g. username) of the user being logged in
   * @param role  the role
   * @param resultHandler  this must return a failure if the check could not be performed - e.g. the principal is not
   *                       known. Otherwise it must return a succeeded result which contains a boolean `true` if the
   *                       principal has the role, or `false` if they do not have the role.
   */
  void hasRole(JsonObject principal, String role, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Handle whether a principal has a permission
   *
   * @param principal   represents the unique id (e.g. username) of the user being logged in
   * @param permission  the permission
   * @param resultHandler  this must return a failure if the check could not be performed - e.g. the principal is not
   *                       known. Otherwise it must return a succeeded result which contains a boolean `true` if the
   *                       principal has the permission, or `false` if they do not have the permission.
   */
  void hasPermission(JsonObject principal, String permission, Handler<AsyncResult<Boolean>> resultHandler);

}
