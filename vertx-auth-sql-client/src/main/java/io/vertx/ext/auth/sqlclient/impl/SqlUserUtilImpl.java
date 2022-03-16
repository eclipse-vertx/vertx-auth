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
package io.vertx.ext.auth.sqlclient.impl;

import io.vertx.core.Future;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.sqlclient.SqlUserUtil;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

import java.security.SecureRandom;

import static io.vertx.ext.auth.impl.Codec.base64Encode;

public class SqlUserUtilImpl implements SqlUserUtil {

  private static final String INSERT_USER = "INSERT INTO user (username, password) VALUES (?, ?)";
  private static final String INSERT_USER_ROLE = "INSERT INTO user_roles (username, role) VALUES (?, ?)";
  private static final String INSERT_ROLE_PERMISSION = "INSERT INTO roles_perms (role, permission) VALUES (?, ?)";

  private final SqlClient client;
  private final HashingStrategy strategy = HashingStrategy.load();
  private final SecureRandom random = new SecureRandom();

  private final String insertUser;
  private final String insertUserRole;
  private final String insertRolePermission;

  public SqlUserUtilImpl(SqlClient client) {
    this(client, INSERT_USER, INSERT_USER_ROLE, INSERT_ROLE_PERMISSION);
  }

  public SqlUserUtilImpl(SqlClient client, String insertUser, String insertUserRole, String insertRolePermission) {
    this.client = client;
    this.insertUser = insertUser;
    this.insertUserRole = insertUserRole;
    this.insertRolePermission = insertRolePermission;
  }

  @Override
  public Future<Void> createUser(String username, String password) {
    if (username == null || password == null) {
      return Future.failedFuture("username or password are null");
    }
    // we have all required data to insert a user
    final byte[] salt = new byte[32];
    random.nextBytes(salt);

    return createHashedUser(
      username,
      strategy.hash("pbkdf2",
        null,
        base64Encode(salt),
        password));
  }

  @Override
  public Future<Void> createHashedUser(String username, String hash) {
    if (username == null || hash == null) {
      return Future.failedFuture("username or password hash are null");
    }

    return client
      .preparedQuery(insertUser)
      .execute(Tuple.of(username, hash))
      .mapEmpty();
  }

  @Override
  public Future<Void> createUserRole(String username, String role) {
    if (username == null || role == null) {
      return Future.failedFuture("username or role are null");
    }

    return client
      .preparedQuery(insertUserRole)
      .execute(Tuple.of(username, role))
      .mapEmpty();
  }

  @Override
  public Future<Void> createRolePermission(String role, String permission) {
    if (role == null || permission == null) {
      return Future.failedFuture("role or permission are null");
    }

    return client
      .preparedQuery(insertRolePermission)
      .execute(Tuple.of(role, permission))
      .mapEmpty();
  }
}
