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
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthentication;
import io.vertx.ext.auth.mongo.MongoAuthenticationOptions;
import io.vertx.ext.auth.mongo.MongoAuthorization;
import io.vertx.ext.mongo.MongoClient;

/**
 * @author mremme
 */
public class AuthMongoExamples {

  public void example1(Vertx vertx, JsonObject mongoClientConfig) {
    MongoClient client = MongoClient.createShared(vertx, mongoClientConfig);
    MongoAuthenticationOptions options = new MongoAuthenticationOptions();
    MongoAuthentication authenticationProvider =
      MongoAuthentication.create(client, options);
  }

  public void example2(MongoAuthentication authProvider) {
    JsonObject authInfo = new JsonObject()
      .put("username", "tim")
      .put("password", "sausages");

    authProvider.authenticate(authInfo)
      .onSuccess(user -> System.out.println("User: " + user.principal()))
      .onFailure(err -> {
        // Failed!
      });
  }

  public void example3(User user, MongoAuthorization mongoAuthZ) {
    mongoAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
        if (PermissionBasedAuthorization.create("commit_code").match(user)) {
          // Has permission!
        }
      });
  }

  public void example4(User user, MongoAuthorization mongoAuthZ) {

    mongoAuthZ.getAuthorizations(user)
      .onSuccess(v -> {
        if (RoleBasedAuthorization.create("manager").match(user)) {
          // Has role!
        }
      });
  }
}
