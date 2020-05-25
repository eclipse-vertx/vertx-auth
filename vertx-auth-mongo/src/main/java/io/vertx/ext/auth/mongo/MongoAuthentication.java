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

package io.vertx.ext.auth.mongo;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.mongo.impl.MongoAuthenticationImpl;
import io.vertx.ext.mongo.MongoClient;

import java.util.Map;

/**
 * An extension of AuthProvider which is using {@link MongoClient} as store
 *
 * @author francoisprunier
 */
@VertxGen
public interface MongoAuthentication extends AuthenticationProvider {

  /**
   * The default name of the collection to be used
   */
  String DEFAULT_COLLECTION_NAME = "user";

  /**
   * The default name of the property for the username, like it is stored in mongodb
   */
  String DEFAULT_USERNAME_FIELD = "username";

  /**
   * The default name of the property for the password, like it is stored in mongodb
   */
  String DEFAULT_PASSWORD_FIELD = "password";

  /**
   * The default name of the property for the username, like it is transported in credentials by method
   * {@link #authenticate(JsonObject, Handler)}
   */
  String DEFAULT_CREDENTIAL_USERNAME_FIELD = DEFAULT_USERNAME_FIELD;

  /**
   * The default name of the property for the password, like it is transported in credentials by method
   * {@link #authenticate(JsonObject, Handler)}
   */
  String DEFAULT_CREDENTIAL_PASSWORD_FIELD = DEFAULT_PASSWORD_FIELD;

  /**
   * The default name of the property for the salt field
   */
  String DEFAULT_SALT_FIELD = "salt";

  /**
   * Creates an instance of MongoAuth by using the given {@link MongoClient} and configuration object.
   *
   * @param mongoClient
   *          an instance of {@link MongoClient} to be used for data storage and retrival
   * @param options
   *          the configuration object for the current instance.
   * @return the created instance of {@link MongoAuthentication}
   */
  static MongoAuthentication create(MongoClient mongoClient, MongoAuthenticationOptions options) {
    return new MongoAuthenticationImpl(mongoClient, options);
  }

  static MongoAuthentication create(MongoClient mongoClient, HashStrategy hashStrategy, MongoAuthenticationOptions options) {
    return new MongoAuthenticationImpl(mongoClient, hashStrategy, DEFAULT_SALT_FIELD, options);
  }

  /**
   * Hashes a password to be stored.
   *
   * See: {@link io.vertx.ext.auth.HashingStrategy#hash(String, Map, String, String)}
   */
  String hash(String id, Map<String, String> params, String salt, String password);

  /**
   * Hashes a password to be stored.
   *
   * See: {@link io.vertx.ext.auth.HashingStrategy#hash(String, Map, String, String)}
   */
  default String hash(String id, String salt, String password) {
    return hash(id, null, salt, password);
  }

  /**
   * Authenticate a User using the specified {@link UsernamePasswordCredentials}
   * 
   * @param credentials
   * @param handler
   */
  void authenticate(UsernamePasswordCredentials credentials, Handler<AsyncResult<User>> handler);

  /**
   * Authenticate a User using the specified {@link UsernamePasswordCredentials}
   * 
   * @param credential
   * @param handler
   */
  default Future<User> authenticate(UsernamePasswordCredentials credentials) {
    Promise<User> promise = Promise.promise();
    authenticate(credentials, promise);
    return promise.future();
  }

}
