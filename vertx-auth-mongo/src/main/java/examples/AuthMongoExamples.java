/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashAlgorithm;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.mongo.MongoClient;

/**
 * @author mremme
 */
public class AuthMongoExamples {

  public void example1(Vertx vertx, JsonObject mongoClientConfig) {
    MongoClient client = MongoClient.createShared(vertx, mongoClientConfig);
    JsonObject authProperties = new JsonObject();
    MongoAuth authProvider = MongoAuth.create(client, authProperties);
  }

  public void example2(MongoAuth authProvider) {
    JsonObject authInfo = new JsonObject()
        .put("username", "tim")
        .put("password", "sausages");
    authProvider.authenticate(authInfo, res -> {
      if (res.succeeded()) {
        User user = res.result();
      } else {
        // Failed!
      }
    });
  }

  public void example3(User user) {

    user.isAuthorized("commit_code", res -> {
      if (res.succeeded()) {
        boolean hasPermission = res.result();
      } else {
        // Failed to
      }
    });

  }

  public void example4(User user) {

    user.isAuthorized(MongoAuth.ROLE_PREFIX + "manager", res -> {
      if (res.succeeded()) {
        boolean hasRole = res.result();
      } else {
        // Failed to
      }
    });

  }

  public void example5(Vertx vertx, JsonObject mongoClientConfig) {
    MongoClient client = MongoClient.createShared(vertx, mongoClientConfig);
    JsonObject authProperties = new JsonObject();
    MongoAuth authProvider = MongoAuth.create(client, authProperties);
    authProvider.setHashAlgorithm(HashAlgorithm.PBKDF2);
  }
}
