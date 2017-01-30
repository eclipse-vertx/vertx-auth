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

import io.vertx.core.*;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthImpl implements AuthProvider, JDBCAuth {

  private JDBCClient client;
  private String authenticateQuery = DEFAULT_AUTHENTICATE_QUERY;
  private String rolesQuery = DEFAULT_ROLES_QUERY;
  private String permissionsQuery = DEFAULT_PERMISSIONS_QUERY;
  private String rolePrefix = DEFAULT_ROLE_PREFIX;
  private JDBCHashStrategy strategy;

  public JDBCAuthImpl(Vertx vertx, JDBCClient client) {
    this.client = client;
    strategy = new DefaultHashStrategy(vertx);
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {

    String username = authInfo.getString("username");
    if (username == null) {
      resultHandler.handle(Future.failedFuture("authInfo must contain username in 'username' field"));
      return;
    }
    String password = authInfo.getString("password");
    if (password == null) {
      resultHandler.handle(Future.failedFuture("authInfo must contain password in 'password' field"));
      return;
    }
    executeQuery(authenticateQuery, new JsonArray().add(username), resultHandler, rs -> {

      switch (rs.getNumRows()) {
        case 0: {
          // Unknown user/password
          resultHandler.handle(Future.failedFuture("Invalid username/password"));
          break;
        }
        case 1: {
          JsonArray row = rs.getResults().get(0);
          String hashedStoredPwd = strategy.getHashedStoredPwd(row);
          String salt = strategy.getSalt(row);
          String hashedPassword = strategy.computeHash(password, salt);
          if (hashedStoredPwd.equals(hashedPassword)) {
            resultHandler.handle(Future.succeededFuture(new JDBCUser(username, this, rolePrefix)));
          } else {
            resultHandler.handle(Future.failedFuture("Invalid username/password"));
          }
          break;
        }
        default: {
          // More than one row returned!
          resultHandler.handle(Future.failedFuture("Failure in authentication"));
          break;
        }
      }
    });
  }

  @Override
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) {
    this.authenticateQuery = authenticationQuery;
    return this;
  }

  @Override
  public JDBCAuth setRolesQuery(String rolesQuery) {
    this.rolesQuery = rolesQuery;
    return this;
  }

  @Override
  public JDBCAuth setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }

  @Override
  public JDBCAuth setRolePrefix(String rolePrefix) {
    this.rolePrefix = rolePrefix;
    return this;
  }

  @Override
  public JDBCAuth setHashStrategy(JDBCHashStrategy strategy) {
    this.strategy = strategy;
    return this;
  }

  <T> void executeQuery(String query, JsonArray params, Handler<AsyncResult<T>> resultHandler,
                                  Consumer<ResultSet> resultSetConsumer) {
    client.getConnection(res -> {
      if (res.succeeded()) {
        SQLConnection conn = res.result();
        conn.queryWithParams(query, params, queryRes -> {
          if (queryRes.succeeded()) {
            ResultSet rs = queryRes.result();
            resultSetConsumer.accept(rs);
          } else {
            resultHandler.handle(Future.failedFuture(queryRes.cause()));
          }
          conn.close(closeRes -> {
          });
        });
      } else {
        resultHandler.handle(Future.failedFuture(res.cause()));
      }
    });
  }


  @Override
  public String computeHash(String password, String salt) {
    return strategy.computeHash(password, salt);
  }

  @Override
  public String generateSalt() {
    return strategy.generateSalt();
  }

  String getRolesQuery() {
    return rolesQuery;
  }

  String getPermissionsQuery() {
    return permissionsQuery;
  }

  private class DefaultHashStrategy implements JDBCHashStrategy {

    private final PRNG random;

    DefaultHashStrategy(Vertx vertx) {
      random = new PRNG(vertx);
    }

    @Override
    public String generateSalt() {
      byte[] salt = new byte[32];
      random.nextBytes(salt);

      return bytesToHex(salt);
    }

    @Override
    public String computeHash(String password, String salt) {
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        String concat = (salt == null ? "" : salt) + password;
        byte[] bHash = md.digest(concat.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(bHash);
      } catch (NoSuchAlgorithmException e) {
        throw new VertxException(e);
      }
    }

    @Override
    public String getHashedStoredPwd(JsonArray row) {
      return row.getString(0);
    }

    @Override
    public String getSalt(JsonArray row) {
      return row.getString(1);
    }

    private final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();

    private String bytesToHex(byte[] bytes) {
      char[] chars = new char[bytes.length * 2];
      for (int i = 0; i < bytes.length; i++) {
        int x = 0xFF & bytes[i];
        chars[i * 2] = HEX_CHARS[x >>> 4];
        chars[1 + i * 2] = HEX_CHARS[0x0F & x];
      }
      return new String(chars);
    }
  }

}
