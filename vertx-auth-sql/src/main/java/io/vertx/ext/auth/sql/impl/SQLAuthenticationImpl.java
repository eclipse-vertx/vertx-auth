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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.sql.SQLAuthentication;
import io.vertx.ext.auth.sql.SQLAuthenticationOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class SQLAuthenticationImpl implements SQLAuthentication {

  private final SqlClient client;
  private final SQLAuthenticationOptions options;
  private final HashingStrategy strategy = HashingStrategy.load();

  public SQLAuthenticationImpl(SqlClient client, SQLAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
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

    client.preparedQuery(options.getAuthenticationQuery(), Tuple.of(username), preparedQuery -> {
      if (preparedQuery.succeeded()) {
        final RowSet<Row> rows = preparedQuery.result();
        switch (rows.size()) {
          case 0: {
            // Unknown user/password
            resultHandler.handle(Future.failedFuture("Invalid username/password"));
            break;
          }
          case 1: {
            Row row = rows.iterator().next();
            String hashedStoredPwd = row.getString(0);
            if (strategy.verify(hashedStoredPwd, password)) {
              resultHandler.handle(Future.succeededFuture(User.create(new JsonObject().put("username", username))));
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
      } else {
        resultHandler.handle(Future.failedFuture(preparedQuery.cause()));
      }
    });
  }
}
