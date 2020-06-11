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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.VertxContextPRNG;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.jdbc.JDBCAuthentication;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
import io.vertx.ext.auth.jdbc.JDBCAuthorization;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthJDBCExamples {

  public void example5(Vertx vertx, JsonObject jdbcClientConfig) {

    JDBCClient jdbcClient = JDBCClient.createShared(vertx, jdbcClientConfig);
    JDBCAuthenticationOptions options = new JDBCAuthenticationOptions();

    JDBCAuthentication authenticationProvider =
      JDBCAuthentication.create(jdbcClient, options);
  }

  public void example6(AuthenticationProvider authProvider) {

    JsonObject authInfo = new JsonObject()
      .put("username", "tim")
      .put("password", "sausages");

    authProvider.authenticate(authInfo)
      .onSuccess(user -> {
        System.out.println("User: " + user.principal());
      })
      .onFailure(err -> {
        // Failed!
      });
  }

  public void example7(User user, JDBCAuthorization jdbcAuthZ) {
    jdbcAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
        if (PermissionBasedAuthorization.create("commit_code").match(user)) {
          // Has permission!
        }
      });
  }

  public void example8(User user, JDBCAuthorization jdbcAuthZ) {
    jdbcAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
      if (RoleBasedAuthorization.create("manager").match(user)) {
        // has role!
      }
    });
  }

  public void example9(JDBCAuthentication jdbcAuth, SQLConnection conn) {

    String hash = jdbcAuth.hash(
      "pbkdf2", // hashing algorithm
      VertxContextPRNG.current().nextString(32), // secure random salt
      "sausages" // password
    );
    // save to the database
    conn.updateWithParams(
      "INSERT INTO user (username, password) VALUES (?, ?)",
      new JsonArray().add("tim").add(hash), res -> {
      if (res.succeeded()) {
        // success!
      }
    });
  }
}
