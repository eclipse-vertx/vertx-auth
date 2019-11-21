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

import java.util.Objects;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.UserImpl;
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationProviderImpl.java
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationProvider;
=======
import io.vertx.ext.auth.jdbc.JDBCAuthentication;
<<<<<<< HEAD
>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationImpl.java
=======
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthenticationImpl implements JDBCAuthentication {

  private JDBCClient client;
<<<<<<< HEAD
=======
  private JDBCAuthenticationOptions options;
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
  private JDBCHashStrategy strategy;
  private JDBCAuthenticationOptions options;

<<<<<<< HEAD
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationProviderImpl.java
  public JDBCAuthenticationProviderImpl(JDBCClient client, JDBCHashStrategy hashStrategy, JDBCAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.strategy = Objects.requireNonNull(hashStrategy);
    this.options = Objects.requireNonNull(options);
=======
  public JDBCAuthenticationImpl(Vertx vertx, JDBCClient client) {
    this.client = client;
    // default strategy
    strategy = JDBCHashStrategy.createSHA512(vertx);
>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationImpl.java
=======
  public JDBCAuthenticationImpl(JDBCClient client, JDBCHashStrategy hashStrategy, JDBCAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
    this.strategy = Objects.requireNonNull(hashStrategy);
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
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

<<<<<<< HEAD
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationProviderImpl.java
=======
  @Override
  public JDBCAuthentication setAuthenticationQuery(String authenticationQuery) {
    this.authenticateQuery = authenticationQuery;
    return this;
  }

  @Override
  public JDBCAuthentication setHashStrategy(JDBCHashStrategy strategy) {
    this.strategy = strategy;
    return this;
  }

>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/impl/JDBCAuthenticationImpl.java
=======
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
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
