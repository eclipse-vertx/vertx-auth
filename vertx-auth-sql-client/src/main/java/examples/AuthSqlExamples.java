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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.VertxContextPRNG;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.sqlclient.SqlAuthentication;
import io.vertx.ext.auth.sqlclient.SqlAuthenticationOptions;
import io.vertx.ext.auth.sqlclient.SqlAuthorization;
import io.vertx.sqlclient.SqlClient;
import io.vertx.sqlclient.Tuple;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthSqlExamples {

  public void example5(Vertx vertx, SqlClient sqlClient) {

    SqlAuthenticationOptions options = new SqlAuthenticationOptions();
    // SQL client can be any of the known implementations
    // *. Postgres
    // *. MySQL
    // *. etc...
    AuthenticationProvider authenticationProvider =
      SqlAuthentication.create(sqlClient, options);
  }

  public void example6(AuthenticationProvider authProvider) {

    JsonObject authInfo = new JsonObject()
      .put("username", "tim")
      .put("password", "sausages");

    authProvider.authenticate(authInfo)
      .onSuccess(user -> System.out.println("User: " + user.principal()))
      .onFailure(err -> {
        // Failed!
      });
  }

  public void example7(User user, SqlAuthorization sqlAuthZ) {
    sqlAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
        if (PermissionBasedAuthorization.create("commit_code").match(user)) {
          // Has permission!
        }
      });
  }

  public void example8(User user, SqlAuthorization sqlAuthZ) {
    sqlAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
        if (RoleBasedAuthorization.create("manager").match(user)) {
          // Has role!
        }
      });
  }

  public void example9(SqlAuthentication sqlAuth, SqlClient sqlClient) {

    String hash = sqlAuth.hash(
      "pbkdf2", // hashing algorithm (OWASP recommended)
      VertxContextPRNG.current().nextString(32), // secure random salt
      "sausages" // password
    );

    // save to the database
    sqlClient
      .preparedQuery("INSERT INTO users (username, password) VALUES ($1, $2)")
      .execute(Tuple.of("tim", hash))
      .onSuccess(rowset -> {
        // password updated
      });
  }
}
