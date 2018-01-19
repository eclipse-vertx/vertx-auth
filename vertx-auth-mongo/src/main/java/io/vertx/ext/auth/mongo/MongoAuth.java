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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.impl.MongoAuthImpl;
import io.vertx.ext.mongo.MongoClient;

import java.util.List;

/**
 * An extension of AuthProvider which is using {@link MongoClient} as store
 *
 * @author mremme
 */
@VertxGen
public interface MongoAuth extends AuthProvider {

  /**
   * The property name to be used to set the name of the collection inside the config
   */
  String PROPERTY_COLLECTION_NAME = "collectionName";

  /**
   * The property name to be used to set the name of the field, where the username is stored inside
   */
  String PROPERTY_USERNAME_FIELD = "usernameField";

  /**
   * The property name to be used to set the name of the field, where the roles are stored inside
   */
  String PROPERTY_ROLE_FIELD = "roleField";

  /**
   * The property name to be used to set the name of the field, where the permissions are stored inside
   */
  String PROPERTY_PERMISSION_FIELD = "permissionField";

  /**
   * The property name to be used to set the name of the field, where the password is stored inside
   */
  String PROPERTY_PASSWORD_FIELD = "passwordField";

  /**
   * The property name to be used to set the name of the field, where the username for the credentials is stored inside
   */
  String PROPERTY_CREDENTIAL_USERNAME_FIELD = "usernameCredentialField";

  /**
   * The property name to be used to set the name of the field, where the password for the credentials is stored inside
   */
  String PROPERTY_CREDENTIAL_PASSWORD_FIELD = "passwordCredentialField";

  /**
   * The property name to be used to set the name of the field, where the SALT is stored inside
   */
  String PROPERTY_SALT_FIELD = "saltField";

  /**
   * The property name to be used to set the name of the field, where the salt style is stored inside
   *
   * @see HashSaltStyle
   */
  String PROPERTY_SALT_STYLE = "saltStyle";

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
   * The default name of the property for the roles, like it is stored in mongodb. Roles are expected to be saved as
   * JsonArray
   */
  String DEFAULT_ROLE_FIELD = "roles";

  /**
   * The default name of the property for the permissions, like it is stored in mongodb. Permissions are expected to be
   * saved as JsonArray
   */
  String DEFAULT_PERMISSION_FIELD = "permissions";

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
   * The prefix which is used by the method {@link User#isAuthorised(String, Handler)} when checking for role access
   */
  String ROLE_PREFIX = "role:";

  /**
   * Creates an instance of MongoAuth by using the given {@link MongoClient} and configuration object. An example for a
   * configuration object:
   *
   * <pre>
   * JsonObject js = new JsonObject();
   * js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
   * </pre>
   *
   * @param mongoClient
   *          an instance of {@link MongoClient} to be used for data storage and retrival
   * @param config
   *          the configuration object for the current instance. By this
   * @return the created instance of {@link MongoAuth}s
   */
  static MongoAuth create(MongoClient mongoClient, JsonObject config) {
    return new MongoAuthImpl(mongoClient, config);
  }

  /**
   * Set the name of the collection to be used. Defaults to {@link #DEFAULT_COLLECTION_NAME}
   *
   * @param collectionName
   *          the name of the collection to be used for storing and reading user data
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setCollectionName(String collectionName);

  /**
   * Set the name of the field to be used for the username. Defaults to {@link #DEFAULT_USERNAME_FIELD}
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setUsernameField(String fieldName);

  /**
   * Set the name of the field to be used for the password Defaults to {@link #DEFAULT_PASSWORD_FIELD}
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setPasswordField(String fieldName);

  /**
   * Set the name of the field to be used for the roles. Defaults to {@link #DEFAULT_ROLE_FIELD}. Roles are expected to
   * be saved as JsonArray
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setRoleField(String fieldName);

  /**
   * Set the name of the field to be used for the permissions. Defaults to {@link #DEFAULT_PERMISSION_FIELD}.
   * Permissions are expected to be saved as JsonArray
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setPermissionField(String fieldName);

  /**
   * Set the name of the field to be used as property for the username in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_USERNAME_FIELD}
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setUsernameCredentialField(String fieldName);

  /**
   * Set the name of the field to be used as property for the password of credentials in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_PASSWORD_FIELD}
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setPasswordCredentialField(String fieldName);

  /**
   * Set the name of the field to be used for the salt. Only used when {@link HashStrategy#setSaltStyle(HashSaltStyle)} is
   * set to {@link HashSaltStyle#COLUMN}
   *
   * @param fieldName
   *          the name of the field to be used
   * @return the current instance itself for fluent calls
   */
  @Fluent
  MongoAuth setSaltField(String fieldName);

  /**
   * The name of the collection used to store User objects inside. Defaults to {@link #DEFAULT_COLLECTION_NAME}
   *
   * @return the collectionName
   */
  String getCollectionName();

  /**
   * Get the name of the field to be used for the username. Defaults to {@link #DEFAULT_USERNAME_FIELD}
   *
   * @return the usernameField
   */
  String getUsernameField();

  /**
   * Get the name of the field to be used for the password Defaults to {@link #DEFAULT_PASSWORD_FIELD}
   *
   * @return the passwordField
   */
  String getPasswordField();

  /**
   * Get the name of the field to be used for the roles. Defaults to {@link #DEFAULT_ROLE_FIELD}. Roles are expected to
   * be saved as JsonArray
   *
   * @return the roleField
   */
  String getRoleField();

  /**
   * Get the name of the field to be used for the permissions. Defaults to {@link #DEFAULT_PERMISSION_FIELD}.
   * Permissions are expected to be saved as JsonArray
   *
   * @return the permissionField
   */
  String getPermissionField();

  /**
   * Get the name of the field to be used as property for the username in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_USERNAME_FIELD}
   *
   * @return the usernameCredentialField
   */
  String getUsernameCredentialField();

  /**
   * Get the name of the field to be used as property for the password of credentials in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_PASSWORD_FIELD}
   *
   * @return the passwordCredentialField
   */
  String getPasswordCredentialField();

  /**
   * Get the name of the field to be used for the salt. Only used when {@link HashStrategy#setSaltStyle(HashSaltStyle)} is
   * set to {@link HashSaltStyle#COLUMN}
   *
   * @return the saltField
   */
  String getSaltField();

  /**
   * The HashStrategy which is used by the current instance
   *
   * @param hashStrategy
   *          the {@link HashStrategy} to be set
   * @return the current instance itself for fluent calls
   *
   */
  @Fluent
  MongoAuth setHashStrategy(HashStrategy hashStrategy);

  /**
   * The HashStrategy which is used by the current instance
   *
   * @return the defined instance of {@link HashStrategy}
   */
  HashStrategy getHashStrategy();

  /**
   * The Hash Algorithm which is used by the current instance
   *
   * @param hashAlgorithm
   *          the {@link HashAlgorithm} to be set
   * @return the current instance itself for fluent calls
   *
   */
  @Fluent
  MongoAuth setHashAlgorithm(HashAlgorithm hashAlgorithm);

  /**
   * Insert a new user into mongo in the convenient way
   *
   * @param username
   *          the username to be set
   * @param password
   *          the passsword in clear text, will be adapted following the definitions of the defined {@link HashStrategy}
   * @param roles
   *          a list of roles to be set
   * @param permissions
   *          a list of permissions to be set
   * @param resultHandler
   *          the ResultHandler will be provided with the id of the generated record
   */
  void insertUser(String username, String password, List<String> roles, List<String> permissions,
      Handler<AsyncResult<String>> resultHandler);

}
