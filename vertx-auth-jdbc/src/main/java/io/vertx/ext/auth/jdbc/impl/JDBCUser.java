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
import io.vertx.ext.auth.jdbc.JDBCAuth;

import java.nio.charset.StandardCharsets;

/**
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCUser extends AbstractUser {

  private JDBCAuthImpl authProvider;
  private String username;
  private JsonObject principal;

  private String rolePrefix;

  public JDBCUser() {
  }

  JDBCUser(String username, JDBCAuthImpl authProvider, String rolePrefix) {
    this.username = username;
    this.authProvider = authProvider;
    this.rolePrefix = rolePrefix;
  }

  @Override
  public String providerId() {
    return JDBCAuth.class.getName();
  }

  @Override
  public void doIsPermitted(String permissionOrRole, Handler<AsyncResult<Boolean>> resultHandler) {
    if (permissionOrRole != null && permissionOrRole.startsWith(rolePrefix)) {
      hasRoleOrPermission(permissionOrRole.substring(rolePrefix.length()), authProvider.getRolesQuery(), resultHandler);
    } else {
      hasRoleOrPermission(permissionOrRole, authProvider.getPermissionsQuery(), resultHandler);
    }
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

    bytes = rolePrefix.getBytes(StandardCharsets.UTF_8);
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

    len = buffer.getInt(pos);
    pos += 4;
    bytes = buffer.getBytes(pos, pos + len);
    rolePrefix = new String(bytes, StandardCharsets.UTF_8);
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
}
