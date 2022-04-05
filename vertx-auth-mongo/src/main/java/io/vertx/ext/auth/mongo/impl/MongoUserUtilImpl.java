/*
 * Copyright 2020 Red Hat, Inc.
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
package io.vertx.ext.auth.mongo.impl;

import io.vertx.core.Future;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.mongo.MongoAuthenticationOptions;
import io.vertx.ext.auth.mongo.MongoAuthorizationOptions;
import io.vertx.ext.auth.mongo.MongoUserUtil;
import io.vertx.ext.mongo.MongoClient;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

import static io.vertx.ext.auth.impl.Codec.base64Encode;

public class MongoUserUtilImpl implements MongoUserUtil {

  private final MongoClient client;
  private final HashingStrategy strategy = HashingStrategy.load();
  private final SecureRandom random = new SecureRandom();

  private final MongoAuthenticationOptions authnOptions;
  private final MongoAuthorizationOptions authzOptions;

  public MongoUserUtilImpl(MongoClient client) {
    this(client, new MongoAuthenticationOptions(), new MongoAuthorizationOptions());
  }

  public MongoUserUtilImpl(MongoClient client, MongoAuthenticationOptions authnOptions, MongoAuthorizationOptions authzOptions) {
    this.client = client;
    this.authnOptions = authnOptions;
    this.authzOptions = authzOptions;
  }

  @Override
  public Future<String> createUser(String username, String password) {
    if (username == null || password == null) {
      return Future.failedFuture("username or password are null");
    }
    // we have all required data to insert a user
    final byte[] salt = new byte[32];
    random.nextBytes(salt);

    return createHashedUser(
      username,
      strategy.hash("pbkdf2",
        null,
        base64Encode(salt),
        password));
  }

  @Override
  public Future<String> createHashedUser(String username, String hash) {
    if (username == null || hash == null) {
      return Future.failedFuture("username or password hash are null");
    }

    return client.save(
      authnOptions.getCollectionName(),
      new JsonObject()
        .put(authnOptions.getUsernameCredentialField(), username)
        .put(authnOptions.getPasswordCredentialField(), hash));
  }

  @Override
  public Future<String> createUserRolesAndPermissions(String username, List<String> roles, List<String> permissions) {
    if (username == null) {
      return Future.failedFuture("username is null");
    }

    return client.save(
      authzOptions.getCollectionName(),
      new JsonObject()
        .put(authzOptions.getUsernameField(), username)
        .put(authzOptions.getRoleField(), roles == null ? Collections.emptyList() : roles)
        .put(authzOptions.getPermissionField(), permissions == null ? Collections.emptyList() : permissions));
  }
}
