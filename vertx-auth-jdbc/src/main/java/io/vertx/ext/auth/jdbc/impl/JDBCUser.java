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

package io.vertx.ext.auth.jdbc.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCUser extends AbstractUser {

  private JDBCAuthImpl authProvider;
  private String username;
  private JsonObject principal;

  public JDBCUser() {
  }

  JDBCUser(String username, JDBCAuthImpl authProvider) {
    this.username = username;
    this.authProvider = authProvider;
  }

  @Override
  public void doHasRole(String role, Handler<AsyncResult<Boolean>> resultHandler) {
    hasRoleOrPermission(role, authProvider.getRolesQuery(), resultHandler);
  }

  @Override
  public void doHasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    hasRoleOrPermission(permission, authProvider.getPermissionsQuery(), resultHandler);
  }

  @Override
  public void doHasRoles(Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    hasAllRolesOrPermissions(roles, authProvider.getRolesQuery(), resultHandler);
  }

  @Override
  public JsonObject principal() {
    if (principal == null) {
      principal = new JsonObject().put("username", username);
    }
    return principal;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    if (authProvider instanceof JDBCAuthImpl) {
      this.authProvider = (JDBCAuthImpl)authProvider;
    } else {
      throw new IllegalArgumentException("Not a JDBCAuthImpl");
    }
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    byte[] bytes = username.getBytes(StandardCharsets.UTF_8);
    buff.appendInt(bytes.length);
    buff.appendBytes(bytes);
  }

  @Override
  public int readFromBuffer(int pos, Buffer buffer) {
    pos = super.readFromBuffer(pos, buffer);
    int len = buffer.getInt(pos);
    pos += 4;
    byte[] bytes = buffer.getBytes(pos, pos + len);
    username = new String(bytes, StandardCharsets.UTF_8);
    pos += len;
    return pos;
  }

  private void hasRoleOrPermission(String roleOrPermission, String query, Handler<AsyncResult<Boolean>> resultHandler) {
    authProvider.executeQuery(query, new JsonArray().add(username), resultHandler, rs -> {
      boolean has = false;
      for (JsonArray result : rs.getResults()) {
        String theRoleOrPermission = result.getString(0);
        if (roleOrPermission.equals(theRoleOrPermission)) {
          resultHandler.handle(Future.succeededFuture(true));
          has = true;
          break;
        }
      }
      if (!has) {
        resultHandler.handle(Future.succeededFuture(false));
      }
    });
  }

  private void hasAllRolesOrPermissions(Set<String> rolesOrPermissions, String query, Handler<AsyncResult<Boolean>> resultHandler) {
    Set<String> copy = new HashSet<>(rolesOrPermissions);
    authProvider.executeQuery(query, new JsonArray().add(username), resultHandler, rs -> {
      boolean hasAll = false;
      for (JsonArray result : rs.getResults()) {
        String theRoleOrPermission = result.getString(0);
        copy.remove(theRoleOrPermission);
        if (copy.isEmpty()) {
          hasAll = true;
          resultHandler.handle(Future.succeededFuture(true));
          break;
        }
      }
      if (!hasAll) {
        resultHandler.handle(Future.succeededFuture(false));
      }
    });
  }
}
