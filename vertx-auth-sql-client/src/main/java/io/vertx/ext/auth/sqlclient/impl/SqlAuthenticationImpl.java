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

package io.vertx.ext.auth.sqlclient.impl;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import io.vertx.core.Future;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.sqlclient.SqlAuthentication;
import io.vertx.ext.auth.sqlclient.SqlAuthenticationOptions;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class SqlAuthenticationImpl implements SqlAuthentication {

  private final SqlClient client;
  private final SqlAuthenticationOptions options;
  private final HashingStrategy strategy = HashingStrategy.load();

  public SqlAuthenticationImpl(SqlClient client, SqlAuthenticationOptions options) {
    this.client = Objects.requireNonNull(client);
    this.options = Objects.requireNonNull(options);
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final UsernamePasswordCredentials authInfo;

    try {
      try {
        authInfo = (UsernamePasswordCredentials) credentials;
      } catch (ClassCastException e) {
        throw new CredentialValidationException("Invalid credentials type", e);
      }
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    return client
      .preparedQuery(options.getAuthenticationQuery())
      .execute(Tuple.of(authInfo.getUsername()))
      .compose(rows -> {
        switch (rows.size()) {
          case 0: {
            // Unknown user/password
            return Future.failedFuture("Invalid username/password");
          }
          case 1: {
            Row row = rows.iterator().next();
            String hashedStoredPwd = row.getString(0);
            if (strategy.verify(hashedStoredPwd, authInfo.getPassword())) {
              User user = User.fromName(authInfo.getUsername());
              // metadata "amr"
              user.principal().put("amr", Collections.singletonList("pwd"));
              return Future.succeededFuture(user);
            } else {
              return Future.failedFuture("Invalid username/password");
            }
          }
          default: {
            // More than one row returned!
            return Future.failedFuture("Failure in authentication");
          }
        }
      });
  }

  @Override
  public String hash(String id, Map<String, String> params, String salt, String password) {
    return strategy.hash(id, params, salt, password);
  }
}
