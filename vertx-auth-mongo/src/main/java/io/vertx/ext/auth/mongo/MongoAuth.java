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
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
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
   * @see SaltStyle
   */
  String PROPERTY_SALT_STYLE = "saltStyle";

  /**
   * The property name to be used to set the name of the field, where the permissionsLookupEnabled is stored inside
   */
  String PROPERTY_PERMISSIONLOOKUP_ENABLED = "permissionsLookupEnabled";

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
   * {@link #init(JsonObject)}
   */
  String DEFAULT_CREDENTIAL_USERNAME_FIELD = DEFAULT_USERNAME_FIELD;

  /**
   * The default name of the property for the password, like it is transported in credentials by method
   * {@link #init(JsonObject)}
   */
  String DEFAULT_CREDENTIAL_PASSWORD_FIELD = DEFAULT_PASSWORD_FIELD;

  /**
   * The default name of the property for the salt field
   */
  String DEFAULT_SALT_FIELD = "salt";

  String ROLE_PREFIX = "role:";

  /**
   * Creates an instance of MongoAuth
   * 
   * @param vertx
   * @param mongoClient
   * @param config
   * @return
   */
  public static MongoAuth create(Vertx vertx, MongoClient mongoClient, JsonObject config) {
    return new MongoAuthImpl(vertx, mongoClient, config);
  }

  /**
   * Set the name of the collection to be used. Defaults to DEFAULT_COLLECTION_NAME
   * 
   * @param collectionName
   * @return
   */
  @Fluent
  public MongoAuth setCollectionName(String collectionName);

  /**
   * Set the name of the field to be used for the username. Defaults to DEFAULT_USERNAME_FIELD
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setUsernameField(String fieldName);

  /**
   * Set the name of the field to be used for the password Defaults to DEFAULT_PASSWORD_FIELD
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setPasswordField(String fieldName);

  /**
   * Set the name of the field to be used for the roles. Defaults to DEFAULT_ROLE_FIELD. Roles are expected to be saved
   * as JsonArray
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setRoleField(String fieldName);

  /**
   * Set the name of the field to be used for the permissions. Defaults to DEFAULT_PERMISSION_FIELD. Permissions are
   * expected to be saved as JsonArray
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setPermissionField(String fieldName);

  /**
   * Set the name of the field to be used as property for the username in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_USERNAME_FIELD}
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setUsernameCredentialField(String fieldName);

  /**
   * Set the name of the field to be used as property for the password of credentials in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}. Defaults to {@link #DEFAULT_CREDENTIAL_PASSWORD_FIELD}
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setPasswordCredentialField(String fieldName);

  /**
   * Set the name of the field to be used for the salt ( if needed )
   * 
   * @param fieldName
   * @return
   */
  @Fluent
  public MongoAuth setSaltField(String fieldName);

  /**
   * @return the collectionName
   */
  public String getCollectionName();

  /**
   * @return the usernameField
   */
  public String getUsernameField();

  /**
   * @return the passwordField
   */
  public String getPasswordField();

  /**
   * @return the roleField
   */
  public String getRoleField();

  /**
   * @return the permissionField
   */
  public String getPermissionField();

  /**
   * @return the usernameCredentialField
   */
  public String getUsernameCredentialField();

  /**
   * @return the passwordCredentialField
   */
  public String getPasswordCredentialField();

  /**
   * @return the saltField
   */
  public String getSaltField();

  /**
   * The HashStrategy which is used by the current instance
   * 
   * @param hashStrategy
   */
  @Fluent
  public MongoAuth setHashStrategy(HashStrategy hashStrategy);

  /**
   * The HashStrategy which is used by the current instance
   * 
   * @return
   */
  public HashStrategy getHashStrategy();

  /**
   * Create a {@link User} with the given parameters
   * 
   * @param username
   * @param password
   * @param roles
   * @param permissions
   * @return
   */
  public User createUser(String username, String password, List<String> roles, List<String> permissions);

  /**
   * Create a {@link User} with the given JsonObject
   * 
   * @param principal
   * @return
   */
  public User createUser(JsonObject principal);

}
