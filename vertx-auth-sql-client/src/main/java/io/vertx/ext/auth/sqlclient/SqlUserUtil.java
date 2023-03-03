/*
 * Copyright 2020 Red Hat, Inc.
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
package io.vertx.ext.auth.sqlclient;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.sqlclient.impl.SqlUserUtilImpl;
import io.vertx.sqlclient.SqlClient;

import java.util.Map;

/**
 * Utility to create users/roles/permissions. This is a helper class and not intended to be a full user
 * management utility. While the standard authentication and authorization interfaces will require usually
 * read only access to the database, in order to use this API a full read/write access must be granted.
 */
@VertxGen
public interface SqlUserUtil {

  /**
   * Create an instance of the user helper.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static SqlUserUtil create(SqlClient client) {
    return new SqlUserUtilImpl(client);
  }

  /**
   * Create an instance of the user helper with custom queries.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static SqlUserUtil create(SqlClient client, String insertUserSQL, String insertUserRoleSQL, String insertRolePermissionSQL) {
    return new SqlUserUtilImpl(client, insertUserSQL, insertUserRoleSQL, insertRolePermissionSQL);
  }

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param password
   *          the passsword in clear text, will be adapted following the definitions of the defined strategy
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  @Deprecated
  default SqlUserUtil createUser(String username, String password, Handler<AsyncResult<Void>> resultHandler) {
    createUser(username, password)
      .onComplete(resultHandler);

    return this;
  }

  /**
   * @see #createUser(String, String, Handler).
   */
  Future<Void> createUser(String username, String password);

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param hash
   *          the password hash, as result of {@link io.vertx.ext.auth.HashingStrategy#hash(String, Map, String, String)}
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  @Deprecated
  default SqlUserUtil createHashedUser(String username, String hash, Handler<AsyncResult<Void>> resultHandler) {
    createHashedUser(username, hash)
      .onComplete(resultHandler);

    return this;
  }

  /**
   * @see #createHashedUser(String, String, Handler).
   */
  Future<Void> createHashedUser(String username, String hash);

  /**
   * Insert a user role into a database.
   *
   * @param username
   *          the username to be set
   * @param role
   *          a to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  @Deprecated
  default SqlUserUtil createUserRole(String username, String role, Handler<AsyncResult<Void>> resultHandler) {
    createUserRole(username, role)
      .onComplete(resultHandler);

    return this;
  }

  /**
   * @see #createUserRole(String, String, Handler).
   */
  Future<Void> createUserRole(String user, String role);

  /**
   * Insert a role permission into a database.
   *
   * @param role
   *          a to be set
   * @param permission
   *          the permission to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  @Deprecated
  default SqlUserUtil createRolePermission(String role, String permission, Handler<AsyncResult<Void>> resultHandler) {
    createRolePermission(role, permission)
      .onComplete(resultHandler);

    return this;
  }

  /**
   * @see #createRolePermission(String, String, Handler).
   */
  Future<Void> createRolePermission(String role, String permission);
}
