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
package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.jdbc.JDBCUserUtil;
import io.vertx.ext.jdbc.JDBCClient;

import java.security.SecureRandom;

import static io.vertx.ext.auth.impl.Codec.base64Encode;

@Deprecated
public class JDBCUserUtilImpl implements JDBCUserUtil {

  private static final String INSERT_USER = "INSERT INTO user (username, password) VALUES (?, ?)";
  private static final String INSERT_USER_ROLE = "INSERT INTO user_roles (username, role) VALUES (?, ?)";
  private static final String INSERT_ROLE_PERMISSION = "INSERT INTO roles_perms (role, permission) VALUES (?, ?)";

  private final JDBCClient client;
  private final HashingStrategy strategy = HashingStrategy.load();
  private final SecureRandom random = new SecureRandom();

  private final String insertUser;
  private final String insertUserRole;
  private final String insertRolePermission;

  public JDBCUserUtilImpl(JDBCClient client) {
    this(client, INSERT_USER, INSERT_USER_ROLE, INSERT_ROLE_PERMISSION);
  }

  public JDBCUserUtilImpl(JDBCClient client, String insertUser, String insertUserRole, String insertRolePermission) {
    this.client = client;
    this.insertUser = insertUser;
    this.insertUserRole = insertUserRole;
    this.insertRolePermission = insertRolePermission;
  }

  @Override
  public JDBCUserUtil createUser(String username, String password, Handler<AsyncResult<Void>> resultHandler) {
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
        base64Encode(salt),
        password),
      resultHandler
    );
  }

  @Override
  public JDBCUserUtil createHashedUser(String username, String hash, Handler<AsyncResult<Void>> resultHandler) {
    if (username == null || hash == null) {
      resultHandler.handle(Future.failedFuture("username or password hash are null"));
      return this;
    }

    client.updateWithParams(insertUser, new JsonArray().add(username).add(hash), insert -> {
      if (insert.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(insert.cause()));
      }
    });
    return this;
  }

  @Override
  public JDBCUserUtil createUserRole(String username, String role, Handler<AsyncResult<Void>> resultHandler) {
    if (username == null || role == null) {
      resultHandler.handle(Future.failedFuture("username or role are null"));
      return this;
    }

    client.updateWithParams(insertUserRole, new JsonArray().add(username).add(role), insert -> {
      if (insert.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(insert.cause()));
      }
    });
    return this;
  }

  @Override
  public JDBCUserUtil createRolePermission(String role, String permission, Handler<AsyncResult<Void>> resultHandler) {
    if (role == null || permission == null) {
      resultHandler.handle(Future.failedFuture("role or permission are null"));
      return this;
    }

    client.updateWithParams(insertRolePermission, new JsonArray().add(role).add(permission), insert -> {
      if (insert.succeeded()) {
        resultHandler.handle(Future.succeededFuture());
      } else {
        resultHandler.handle(Future.failedFuture(insert.cause()));
      }
    });
    return this;
  }
}
