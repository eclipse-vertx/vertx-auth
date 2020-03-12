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
package io.vertx.ext.auth.mongo;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.ext.auth.mongo.impl.MongoUserUtilImpl;
import io.vertx.ext.mongo.MongoClient;

import java.util.List;
import java.util.Map;

/**
 * Utility to create users/roles/permissions. This is a helper class and not intended to be a full user
 * management utility. While the standard authentication and authorization interfaces will require usually
 * read only access to the database, in order to use this API a full read/write access must be granted.
 */
@VertxGen
public interface MongoUserUtil {

  /**
   * Create an instance of the user helper.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static MongoUserUtil create(MongoClient client) {
    return new MongoUserUtilImpl(client);
  }

  /**
   * Create an instance of the user helper with custom queries.
   * @param client the client with write rights to the database.
   * @return the instance
   */
  static MongoUserUtil create(MongoClient client, MongoAuthenticationOptions authenticationOptions, MongoAuthorizationOptions authorizationOptions) {
    return new MongoUserUtilImpl(client, authenticationOptions, authorizationOptions);
  }

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param password
   *          the passsword in clear text, will be adapted following the definitions of the defined strategy
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  MongoUserUtil createUser(String username, String password, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createUser(String, String, Handler).
   */
  default Future<Void> createUser(String username, String password) {
    Promise<Void> promise = Promise.promise();
    createUser(username, password, promise);
    return promise.future();
  }

  /**
   * Insert a user into a database.
   *
   * @param username
   *          the username to be set
   * @param hash
   *          the password hash, as result of {@link io.vertx.ext.auth.HashingStrategy#hash(String, Map, String, String)}
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  MongoUserUtil createHashedUser(String username, String hash, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createHashedUser(String, String, Handler).
   */
  default Future<Void> createHashedUser(String username, String hash) {
    Promise<Void> promise = Promise.promise();
    createHashedUser(username, hash, promise);
    return promise.future();
  }

  /**
   * Insert a user role into a database.
   *
   * @param username
   *          the username to be set
   * @param roles
   *          a to be set
   * @param permissions
   *          a to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the result of the operation
   * @return fluent self
   */
  @Fluent
  MongoUserUtil createUserRolesAndPermissions(String username, List<String> roles, List<String> permissions, Handler<AsyncResult<Void>> resultHandler);

  /**
   * @see #createUserRolesAndPermissions(String, List, List, Handler).
   */
  default Future<Void> createUserRolesAndPermissions(String user, List<String> roles, List<String> permissions) {
    Promise<Void> promise = Promise.promise();
    createUserRolesAndPermissions(user, roles, permissions, promise);
    return promise.future();
  }
}
