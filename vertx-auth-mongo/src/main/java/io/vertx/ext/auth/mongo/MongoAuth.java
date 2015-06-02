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

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.impl.MongoAuthImpl;
import io.vertx.ext.auth.mongo.impl.MongoUserFactory;
import io.vertx.ext.mongo.MongoService;

/**
 * @author mremme
 */

public interface MongoAuth extends AuthProvider {

  /**
   * This propertyname is used to set the logged in principal into the context
   */
  public static final String CURRENT_PRINCIPAL_PROPERTY         = "current.principal";

  /**
   * The property name to be used to set the name of the collection inside the config
   */
  public static final String PROPERTY_COLLECTION_NAME           = "collectionName";

  /**
   * The property name to be used to set the name of the field, where the username is stored inside
   */
  public static final String PROPERTY_USERNAME_FIELD            = "usernameField";

  /**
   * The property name to be used to set the name of the field, where the roles are stored inside
   */
  public static final String PROPERTY_ROLE_FIELD                = "roleField";

  /**
   * The property name to be used to set the name of the field, where the permissions are stored inside
   */
  public static final String PROPERTY_PERMISSION_FIELD          = "permissionField";

  /**
   * The property name to be used to set the name of the field, where the password is stored inside
   */
  public static final String PROPERTY_PASSWORD_FIELD            = "passwordField";

  /**
   * The property name to be used to set the name of the field, where the username for the credentials is stored inside
   */
  public static final String PROPERTY_CREDENTIAL_USERNAME_FIELD = "usernameCredentialField";

  /**
   * The property name to be used to set the name of the field, where the password for the credentials is stored inside
   */
  public static final String PROPERTY_CREDENTIAL_PASSWORD_FIELD = "passwordCredentialField";

  /**
   * The property name to be used to set the name of the field, where the SALT is stored inside
   */
  public static final String PROPERTY_SALT_FIELD                = "saltField";

  /**
   * The property name to be used to set the name of the field, where the salt style is stored inside
   * 
   * @see SaltStyle
   */
  public static final String PROPERTY_SALT_STYLE                = "saltStyle";

  /**
   * The property name to be used to set the name of the field, where the permissionsLookupEnabled is stored inside
   */
  public static final String PROPERTY_PERMISSIONLOOKUP_ENABLED  = "permissionsLookupEnabled";

  /**
   * The default name of the collection to be used
   */
  public static final String DEFAULT_COLLECTION_NAME            = "user";

  /**
   * The default name of the property for the username, like it is stored in mongodb
   */
  public static final String DEFAULT_USERNAME_FIELD             = "username";

  /**
   * The default name of the property for the password, like it is stored in mongodb
   */
  public static final String DEFAULT_PASSWORD_FIELD             = "password";

  /**
   * The default name of the property for the roles, like it is stored in mongodb. Roles are expected to be saved as
   * JsonArray
   */
  public static final String DEFAULT_ROLE_FIELD                 = "roles";

  /**
   * The default name of the property for the permissions, like it is stored in mongodb. Permissions are expected to be
   * saved as
   * JsonArray
   */
  public static final String DEFAULT_PERMISSION_FIELD           = "permissions";

  /**
   * The default name of the property for the username, like it is transported in credentials by method
   * {@link #init(JsonObject)}
   */
  public static final String DEFAULT_CREDENTIAL_USERNAME_FIELD  = DEFAULT_USERNAME_FIELD;

  /**
   * The default name of the property for the password, like it is transported in credentials by method
   * {@link #init(JsonObject)}
   */
  public static final String DEFAULT_CREDENTIAL_PASSWORD_FIELD  = DEFAULT_PASSWORD_FIELD;

  /**
   * The default name of the property for the salt field
   */
  public static final String DEFAULT_SALT_FIELD                 = "salt";

  public static final String ROLE_PREFIX                        = "role:";

  /**
   * Creates an instance of MongoAuth by using the {@link MongoUserFactory}
   * 
   * @param vertx
   * @param serviceName
   * @param config
   * @return
   */
  public static MongoAuth create(Vertx vertx, String serviceName, JsonObject config) {
    return new MongoAuthImpl(vertx, serviceName, config, null);
  }

  /**
   * Creates an instance of MongoAuth by using the {@link MongoUserFactory}
   * 
   * @param vertx
   * @param service
   * @param config
   * @return
   */
  public static MongoAuth create(Vertx vertx, MongoService service, JsonObject config) {
    return new MongoAuthImpl(vertx, service, config, null);
  }

  /**
   * Creates an instance of MongoAuth with the defined userfactory
   * 
   * @param vertx
   * @param serviceName
   * @param config
   * @userFactory the instance of {@link UserFactory} to be used
   * @return
   */
  public static MongoAuth create(Vertx vertx, String serviceName, JsonObject config, UserFactory userFactory) {
    return new MongoAuthImpl(vertx, serviceName, config, userFactory);
  }

  /**
   * Creates an instance of MongoAuth with the defined userfactory
   * 
   * @param vertx
   * @param service
   * @param config
   * @userFactory the instance of {@link UserFactory} to be used
   * @return
   */
  public static MongoAuth create(Vertx vertx, MongoService service, JsonObject config, UserFactory userFactory) {
    return new MongoAuthImpl(vertx, service, config, userFactory);
  }

  /**
   * Set the name of the collection to be used. Defaults to DEFAULT_COLLECTION_NAME
   * 
   * @param collectionName
   * @return
   */
  public MongoAuth setCollectionName(String collectionName);

  /**
   * Set the name of the field to be used for the username. Defaults to DEFAULT_USERNAME_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setUsernameField(String fieldName);

  /**
   * Set the name of the field to be used for the password Defaults to DEFAULT_PASSWORD_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setPasswordField(String fieldName);

  /**
   * Set the name of the field to be used for the roles. Defaults to DEFAULT_ROLE_FIELD. Roles are expected to be saved
   * as JsonArray
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setRoleField(String fieldName);

  /**
   * Set the name of the field to be used for the permissions. Defaults to DEFAULT_PERMISSION_FIELD. Permissions are
   * expected to be saved
   * as JsonArray
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setPermissionField(String fieldName);

  /**
   * Set the name of the field to be used as property for the username in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}.
   * Defaults to {@link #DEFAULT_CREDENTIAL_USERNAME_FIELD}
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setUsernameCredentialField(String fieldName);

  /**
   * Set the name of the field to be used as property for the password of credentials in the method
   * {@link #authenticate(JsonObject, io.vertx.core.Handler)}.
   * Defaults to {@link #DEFAULT_CREDENTIAL_PASSWORD_FIELD}
   * 
   * @param fieldName
   * @return
   */
  public MongoAuth setPasswordCredentialField(String fieldName);

  /**
   * Set the name of the field to be used for the salt ( if needed )
   * 
   * @param fieldName
   * @return
   */
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
   * Get the {@link UserFactory} which is used to create instances of {@link User}
   * 
   * @return
   */
  public UserFactory getUserFactory();

  /**
   * The {@link UserFactory} to be used with the current instance.
   * 
   * @param userFactory
   */
  public void setUserFactory(UserFactory userFactory);

  /**
   * The HashStrategy which is used by the current instance
   * 
   * @param hashStrategy
   */
  public void setHashStrategy(HashStrategy hashStrategy);

  /**
   * The HashStrategy which is used by the current instance
   * 
   * @return
   */
  public HashStrategy getHashStrategy();

}
