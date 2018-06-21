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
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.ext.sql.SQLConnection;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthJDBCExamples {


  public void example5(Vertx vertx, JsonObject jdbcClientConfig) {

    JDBCClient jdbcClient = JDBCClient.createShared(vertx, jdbcClientConfig);

    JDBCAuth authProvider = JDBCAuth.create(vertx, jdbcClient);
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

  public void example7(User user) {

    user.isAuthorized("commit_code", res -> {
      if (res.succeeded()) {
        boolean hasPermission = res.result();
      } else {
        // Failed to
      }
    });

  }

  public void example8(User user) {

    user.isAuthorized("role:manager", res -> {
      if (res.succeeded()) {
        boolean hasRole = res.result();
      } else {
        // Failed to
      }
    });

  }

  public void example9(JDBCAuth auth, SQLConnection conn) {

    String salt = auth.generateSalt();
    String hash = auth.computeHash("sausages", salt);
    // save to the database
    conn.updateWithParams("INSERT INTO user VALUES (?, ?, ?)", new JsonArray().add("tim").add(hash).add(salt), res -> {
      if (res.succeeded()) {
        // success!
      }
    });
  }

  public void example10(JDBCAuth auth) {
    auth.setNonces(new JsonArray().add("random_hash_1").add("random_hash_1"));
  }

  public void example11(JDBCAuth auth, SQLConnection conn) {

    auth.setNonces(new JsonArray().add("random_hash_1").add("random_hash_1"));

    String salt = auth.generateSalt();
    // we will pick the second nonce
    String hash = auth.computeHash("sausages", salt, 1);
    // save to the database
    conn.updateWithParams("INSERT INTO user VALUES (?, ?, ?)", new JsonArray().add("tim").add(hash).add(salt), res -> {
      if (res.succeeded()) {
        // success!
      }
    });
  }
}
