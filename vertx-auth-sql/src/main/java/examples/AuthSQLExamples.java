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

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.VertxContextPRNG;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.sql.SQLAuthentication;
import io.vertx.ext.auth.sql.SQLAuthenticationOptions;
import io.vertx.ext.auth.sql.SQLAuthorization;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthSQLExamples {

  public void example5(Vertx vertx, SqlClient sqlClient) {

    SQLAuthenticationOptions options = new SQLAuthenticationOptions();
    // SQL client can be any of the known implementations
    // *. Postgres
    // *. MySQL
    // *. etc...
    AuthenticationProvider authenticationProvider = SQLAuthentication.create(sqlClient, options);
  }

  public void example6(AuthProvider authProvider) {

    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");

    authProvider.authenticate(authInfo, res -> {
      if (res.succeeded()) {
        User user = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example7(User user, SQLAuthorization jdbcAuthZ) {
    jdbcAuthZ.getAuthorizations(user, res -> {
      if (res.succeeded()) {
        if (PermissionBasedAuthorization.create("commit_code").match(user)) {
          // Has permission!
        }
      }
    });
  }

  public void example8(User user, SQLAuthorization jdbcAuthZ) {
    jdbcAuthZ.getAuthorizations(user, res -> {
      if (res.succeeded()) {
        if (RoleBasedAuthorization.create("manager").match(user)) {
          // has role!
        }
      }
    });
  }

  public void example9(SQLAuthentication jdbcAuth, SqlClient sqlClient) {

    String hash = jdbcAuth.hash(
      "pkdbf2", // hashing algorithm (OWASP recommended)
      VertxContextPRNG.current().nextString(32), // secure random salt
      "sausages" // password
    );
    // save to the database
    sqlClient.preparedQuery("INSERT INTO user (username, password) VALUES (?, ?)", Tuple.of("tim", hash), ar -> {
      if (ar.succeeded()) {
        // password updated
      }
    });
  }
}
