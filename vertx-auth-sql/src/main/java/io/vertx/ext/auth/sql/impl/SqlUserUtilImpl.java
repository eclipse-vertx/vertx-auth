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
package io.vertx.ext.auth.sql.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.sql.SqlUserUtil;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

import java.security.SecureRandom;
import java.util.Base64;

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
  public SqlUserUtil createUser(String username, String password, Handler<AsyncResult<Void>> resultHandler) {
    if (username == null || password == null) {
      resultHandler.handle(Future.failedFuture("username or password are null"));
      return this;
    }
    // we have all required data to insert a user
    final byte[] salt = new byte[32];
    random.nextBytes(salt);

    return createHashedUser(
      username,
      strategy.hash("pbkdf2",
        null,
        Base64.getMimeEncoder().encodeToString(salt),
        password),
      resultHandler
    );
  }

  @Override
  public SqlUserUtil createHashedUser(String username, String hash, Handler<AsyncResult<Void>> resultHandler) {
    if (username == null || hash == null) {
      resultHandler.handle(Future.failedFuture("username or password hash are null"));
      return this;
    }

    client.preparedQuery(insertUser).execute(Tuple.of(username, hash), prepare -> {
      if (prepare.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(prepare.cause()));
      }
    });
    return this;
  }

  @Override
  public SqlUserUtil createUserRole(String username, String role, Handler<AsyncResult<Void>> resultHandler) {
    if (username == null || role == null) {
      resultHandler.handle(Future.failedFuture("username or role are null"));
      return this;
    }

    client.preparedQuery(insertUserRole).execute(Tuple.of(username, role), prepare -> {
      if (prepare.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(prepare.cause()));
      }
    });
    return this;
  }

  @Override
  public SqlUserUtil createRolePermission(String role, String permission, Handler<AsyncResult<Void>> resultHandler) {
    if (role == null || permission == null) {
      resultHandler.handle(Future.failedFuture("role or permission are null"));
      return this;
    }

    client.preparedQuery(insertRolePermission).execute(Tuple.of(role, permission), insert -> {
      if (insert.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(insert.cause()));
      }
    });
    return this;
  }
}
