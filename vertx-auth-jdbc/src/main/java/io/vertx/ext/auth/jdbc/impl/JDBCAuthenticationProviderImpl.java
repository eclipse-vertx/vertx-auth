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
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationProvider;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthenticationProviderImpl implements JDBCAuthenticationProvider {

  /**
   * The default query to be used for authentication
   */
  private final static String DEFAULT_AUTHENTICATE_QUERY = "SELECT PASSWORD, PASSWORD_SALT FROM USER WHERE USERNAME = ?";

  private JDBCClient client;
  private String authenticateQuery = DEFAULT_AUTHENTICATE_QUERY;
  private JDBCHashStrategy strategy;

  public JDBCAuthenticationProviderImpl(Vertx vertx, JDBCClient client) {
    this.client = client;
    // default strategy
    strategy = JDBCHashStrategy.createSHA512(vertx);
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
    executeQuery(authenticateQuery, new JsonArray().add(username), queryResponse -> {
      if (queryResponse.succeeded()) {
        ResultSet rs = queryResponse.result();
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
            // extract the version (-1 means no version)
            int version = -1;
            int sep = hashedStoredPwd.lastIndexOf('$');
            if (sep != -1) {
              try {
                version = Integer.parseInt(hashedStoredPwd.substring(sep + 1));
              } catch (NumberFormatException e) {
                // the nonce version is not a number
                resultHandler.handle(Future.failedFuture("Invalid nonce version: " + version));
                return;
              }
            }
            String hashedPassword = strategy.computeHash(password, salt, version);
            if (JDBCHashStrategy.isEqual(hashedStoredPwd, hashedPassword)) {
              User user = new UserImpl(new JsonObject().put("username", username));
              user.setAuthProvider(this);
              resultHandler.handle(Future.succeededFuture(user));
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
      }
      else {
        resultHandler.handle(Future.failedFuture(queryResponse.cause()));
      }
    });
  }

  @Override
  public JDBCAuthenticationProvider setAuthenticationQuery(String authenticationQuery) {
    this.authenticateQuery = authenticationQuery;
    return this;
  }

  @Override
  public JDBCAuthenticationProvider setHashStrategy(JDBCHashStrategy strategy) {
    this.strategy = strategy;
    return this;
  }

  void executeQuery(String query, JsonArray params, Handler<AsyncResult<ResultSet>> resultHandler) {
    client.getConnection(res -> {
      if (res.succeeded()) {
        SQLConnection connection = res.result();
        connection.queryWithParams(query, params, queryResponse -> {
          resultHandler.handle(queryResponse);
          // close the connection right away
          connection.close();
        });
      } else {
        resultHandler.handle(Future.failedFuture(res.cause()));
      }
    });
  }

  @Override
  public String computeHash(String password, String salt, int version) {
    return strategy.computeHash(password, salt, version);
  }

  @Override
  public String generateSalt() {
    return strategy.generateSalt();
  }

  @Override
  public JDBCAuthenticationProvider setNonces(JsonArray nonces) {
    strategy.setNonces(nonces);
    return this;
  }

}
