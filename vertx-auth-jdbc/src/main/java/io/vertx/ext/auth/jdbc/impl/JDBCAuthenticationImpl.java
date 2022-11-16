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

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.jdbc.JDBCAuthentication;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.ResultSet;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@Deprecated
public class JDBCAuthenticationImpl implements JDBCAuthentication {

  private final HashingStrategy strategy = HashingStrategy.load();

  private final JDBCClient client;
  private JDBCHashStrategy legacyStrategy;
  private final JDBCAuthenticationOptions options;

  public JDBCAuthenticationImpl(JDBCClient client, JDBCHashStrategy hashStrategy, JDBCAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
    this.legacyStrategy = Objects.requireNonNull(hashStrategy);
  }

  public JDBCAuthenticationImpl(JDBCClient client, JDBCAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
  }

  @Override
  public Future<User> authenticate(JsonObject authInfo) {
    return authenticate(new UsernamePasswordCredentials(authInfo));
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final UsernamePasswordCredentials authInfo;
    try {
      authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    Promise<User> promise = Promise.promise();

    executeQuery(options.getAuthenticationQuery(), new JsonArray().add(authInfo.getUsername()), queryResponse -> {
      if (queryResponse.succeeded()) {
        ResultSet rs = queryResponse.result();
        switch (rs.getNumRows()) {
          case 0: {
            // Unknown user/password
            promise.fail("Invalid username/password");
            break;
          }
          case 1: {
            JsonArray row = rs.getResults().get(0);
            try {
              if (verify(row, authInfo.getPassword())) {
                User user = User.fromName(authInfo.getUsername());
                // metadata "amr"
                user.principal().put("amr", Collections.singletonList("pwd"));
                promise.complete(user);
              } else {
                promise.fail("Invalid username/password");
              }
            } catch (RuntimeException e) {
              promise.fail(e);
            }
            break;
          }
          default: {
            // More than one row returned!
            promise.fail("Failure in authentication");
            break;
          }
        }
      } else {
        promise.fail(queryResponse.cause());
      }
    });

    return promise.future();
  }

  private boolean verify(JsonArray row, String password) {
    String hash = row.getString(0);
    if (hash.charAt(0) != '$') {
      // this isn't a phc-string, it's legacy
      if (legacyStrategy == null) {
        throw new IllegalStateException("JDBC Authentication cannot handle legacy hashes without a JDBCStrategy");
      }
      String salt = row.getString(1);
      // extract the version (-1 means no version)
      int version = -1;
      int sep = hash.lastIndexOf('$');
      if (sep != -1) {
        try {
          version = Integer.parseInt(hash.substring(sep + 1));
        } catch (NumberFormatException e) {
          // the nonce version is not a number
          throw new IllegalStateException("Invalid nonce version: " + version);
        }
      }
      return JDBCHashStrategy.isEqual(hash, legacyStrategy.computeHash(password, salt, version));
    } else {
      return strategy.verify(hash, password);
    }
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
  public String hash(String id, Map<String, String> params, String salt, String password) {
    return strategy.hash(id, params, salt, password);
  }
}
