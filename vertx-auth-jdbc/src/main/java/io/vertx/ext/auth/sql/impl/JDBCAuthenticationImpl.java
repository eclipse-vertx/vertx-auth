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

package io.vertx.ext.auth.sql.impl;

import java.util.Objects;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.sql.JDBCAuthentication;
import io.vertx.ext.auth.sql.JDBCAuthenticationOptions;
import io.vertx.ext.auth.sql.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthenticationImpl implements JDBCAuthentication {

  private JDBCClient client;
  private JDBCHashStrategy strategy;
  private JDBCAuthenticationOptions options;

  public JDBCAuthenticationImpl(JDBCClient client, JDBCHashStrategy hashStrategy, JDBCAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
    this.strategy = Objects.requireNonNull(hashStrategy);
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
    executeQuery(options.getAuthenticationQuery(), new JsonArray().add(username), queryResponse -> {
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

}
