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

package io.vertx.ext.auth.mongo.impl;

import java.util.List;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.mongo.HashAlgorithm;
import io.vertx.ext.auth.mongo.HashSaltStyle;
import io.vertx.ext.auth.mongo.HashStrategy;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.auth.mongo.MongoAuthentication;
import io.vertx.ext.auth.mongo.MongoAuthenticationOptions;
import io.vertx.ext.auth.mongo.MongoAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthorizationOptions;
import io.vertx.ext.mongo.MongoClient;

/**
 * An implementation of {@link MongoAuth}
 *
 * @author mremme
 */
@Deprecated
public class MongoAuthImpl implements MongoAuth {
  final static String PROPERTY_FIELD_SALT = "__field-salt__";
  final static String PROPERTY_FIELD_PASSWORD = "__field-password__";
  private static final Logger log = LoggerFactory.getLogger(MongoAuthImpl.class);
  private static final String PROVIDER_ID = "mongo-authentication";
  private MongoClient mongoClient;
  private String saltField = DEFAULT_SALT_FIELD;

  private MongoAuthentication mongoAuthentication;
  private MongoAuthenticationOptions mongoAuthenticationOptions;
  private MongoAuthorization mongoAuthorization;
  private MongoAuthorizationOptions mongoAuthorizationOptions;

  private JsonObject config;

  private HashStrategy hashStrategy;

  /**
   * Creates a new instance
   *
   * @param mongoClient
   *          the {@link MongoClient} to be used
   * @param config
   *          the config for configuring the new instance
   * @see MongoAuth#create(MongoClient, JsonObject)
   */
  public MongoAuthImpl(MongoClient mongoClient, JsonObject config) {
    this.mongoClient = mongoClient;
    this.config = config;
    this.mongoAuthenticationOptions = new MongoAuthenticationOptions();
    this.mongoAuthorizationOptions = new MongoAuthorizationOptions();
    init();
    this.mongoAuthentication = MongoAuthentication.create(mongoClient, getHashStrategy(), mongoAuthenticationOptions);
    this.mongoAuthorization = MongoAuthorization.create(PROVIDER_ID, mongoClient, mongoAuthorizationOptions);
  }

  @Override
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(new UsernamePasswordCredentials(credentials), resultHandler);
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {

    try {
      UsernamePasswordCredentials authInfo = (UsernamePasswordCredentials) credentials;
      authInfo.checkValid(null);

      mongoAuthentication.authenticate(authInfo, authenticationResult -> {
        if (authenticationResult.failed()) {
          resultHandler.handle(Future.failedFuture(authenticationResult.cause()));
        } else {
          User user = authenticationResult.result();
          mongoAuthorization.getAuthorizations(user, userAuthorizationResult -> {
            if (userAuthorizationResult.failed()) {
              // what do we do in case something goes wrong during authorizationProvider but we've got a correct user ?
              // for now, lets return a failure
              resultHandler.handle(Future.failedFuture(userAuthorizationResult.cause()));
            }
            else {
              resultHandler.handle(Future.succeededFuture(user));
            }
          });
        }
      });
    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#insertUser(java.lang.String, java.lang.String, java.util.List,
   * java.util.List, io.vertx.core.Handler)
   */
  @Override
  public void insertUser(String username, String password, List<String> roles, List<String> permissions,
      Handler<AsyncResult<String>> resultHandler) {
    JsonObject principal = new JsonObject();
    principal.put(getUsernameField(), username);

    if (roles != null) {
      principal.put(mongoAuthorizationOptions.getRoleField(), new JsonArray(roles));
    }

    if (permissions != null) {
      principal.put(mongoAuthorizationOptions.getPermissionField(), new JsonArray(permissions));
    }

    if (getHashStrategy().getSaltStyle() == HashSaltStyle.COLUMN) {
      principal.put(getSaltField(), DefaultHashStrategy.generateSalt());
    }

    User user = createUser(principal);
    String cryptPassword = getHashStrategy().computeHash(password, user);
    principal.put(getPasswordField(), cryptPassword);

    mongoClient.save(getCollectionName(), user.principal(), resultHandler);
  }

  private User createUser(JsonObject json) {
    User user = new UserImpl(json);
    json.put(PROPERTY_FIELD_SALT, getSaltField());
    json.put(PROPERTY_FIELD_PASSWORD, getPasswordField());
    JsonArray roles = json.getJsonArray(mongoAuthorizationOptions.getRoleField());
    if (roles!=null) {
      for (int i=0; i<roles.size(); i++) {
        String role = roles.getString(i);
        user.authorizations().add(PROVIDER_ID, RoleBasedAuthorization.create(role));
      }
    }
    JsonArray permissions = json.getJsonArray(mongoAuthorizationOptions.getPermissionField());
    if (permissions!=null) {
      for (int i=0; i<permissions.size(); i++) {
        String permission = permissions.getString(i);
        user.authorizations().add(PROVIDER_ID, PermissionBasedAuthorization.create(permission));
      }
    }
    user.setAuthProvider(this);
    return user;
  }

  /**
   * Initializes the current provider by using the current config object
   */
  private void init() {

    String collectionName = config.getString(PROPERTY_COLLECTION_NAME);
    if (collectionName != null) {
      setCollectionName(collectionName);
    }

    String usernameField = config.getString(PROPERTY_USERNAME_FIELD);
    if (usernameField != null) {
      setUsernameField(usernameField);
    }

    String passwordField = config.getString(PROPERTY_PASSWORD_FIELD);
    if (passwordField != null) {
      setPasswordField(passwordField);
    }

    String roleField = config.getString(PROPERTY_ROLE_FIELD);
    if (roleField != null) {
      setRoleField(roleField);
    }

    String permissionField = config.getString(PROPERTY_PERMISSION_FIELD);
    if (permissionField != null) {
      setPermissionField(permissionField);
    }

    String usernameCredField = config.getString(PROPERTY_CREDENTIAL_USERNAME_FIELD);
    if (usernameCredField != null) {
      setUsernameCredentialField(usernameCredField);
    }

    String passwordCredField = config.getString(PROPERTY_CREDENTIAL_PASSWORD_FIELD);
    if (passwordCredField != null) {
      setPasswordCredentialField(passwordCredField);
    }

    String saltField = config.getString(PROPERTY_SALT_FIELD);
    if (saltField != null) {
      setSaltField(saltField);
    }

    String saltstyle = config.getString(PROPERTY_SALT_STYLE);
    if (saltstyle != null) {
      getHashStrategy().setSaltStyle(HashSaltStyle.valueOf(saltstyle));
    }

  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setCollectionName(java.lang.String)
   */
  @Override
  public MongoAuth setCollectionName(String collectionName) {
    this.mongoAuthenticationOptions.setCollectionName(collectionName);
    this.mongoAuthorizationOptions.setCollectionName(collectionName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setUsernameField(java.lang.String)
   */
  @Override
  public MongoAuth setUsernameField(String fieldName) {
    this.mongoAuthenticationOptions.setUsernameField(fieldName);
    this.mongoAuthorizationOptions.setUsernameField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setPasswordField(java.lang.String)
   */
  @Override
  public MongoAuth setPasswordField(String fieldName) {
    this.mongoAuthenticationOptions.setPasswordField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setRoleField(java.lang.String)
   */
  @Override
  public MongoAuth setRoleField(String fieldName) {
    this.mongoAuthorizationOptions.setRoleField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setUsernameCredentialField(java.lang. String)
   */
  @Override
  public MongoAuth setUsernameCredentialField(String fieldName) {
    this.mongoAuthenticationOptions.setUsernameCredentialField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setPasswordCredentialField(java.lang. String)
   */
  @Override
  public MongoAuth setPasswordCredentialField(String fieldName) {
    this.mongoAuthenticationOptions.setPasswordCredentialField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setSaltField(java.lang.String)
   */
  @Override
  public MongoAuth setSaltField(String fieldName) {
    this.saltField = fieldName;
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getCollectionName()
   */
  @Override
  public String getCollectionName() {
    return mongoAuthenticationOptions.getCollectionName();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getUsernameField()
   */
  @Override
  public final String getUsernameField() {
    return mongoAuthenticationOptions.getUsernameField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getPasswordField()
   */
  @Override
  public final String getPasswordField() {
    return mongoAuthenticationOptions.getPasswordField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getRoleField()
   */
  @Override
  public final String getRoleField() {
    return mongoAuthorizationOptions.getRoleField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getUsernameCredentialField()
   */
  @Override
  public final String getUsernameCredentialField() {
    return mongoAuthenticationOptions.getUsernameCredentialField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getPasswordCredentialField()
   */
  @Override
  public final String getPasswordCredentialField() {
    return mongoAuthenticationOptions.getPasswordCredentialField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getSaltField()
   */
  @Override
  public final String getSaltField() {
    return saltField;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setPermissionField(java.lang.String)
   */
  @Override
  public MongoAuth setPermissionField(String fieldName) {
    this.mongoAuthorizationOptions.setPermissionField(fieldName);
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getPermissionField()
   */
  @Override
  public String getPermissionField() {
    return this.mongoAuthorizationOptions.getPermissionField();
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setHashStrategy(io.vertx.ext.auth.mongo.HashStrategy)
   */
  @Override
  public MongoAuth setHashStrategy(HashStrategy hashStrategy) {
    this.hashStrategy = hashStrategy;
    return this;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#getHashStrategy()
   */
  @Override
  public HashStrategy getHashStrategy() {
    if (hashStrategy == null)
      hashStrategy = new DefaultHashStrategy();
    return hashStrategy;
  }

  /*
   * (non-Javadoc)
   *
   * @see io.vertx.ext.auth.mongo.MongoAuth#setHashAlgorithm(io.vertx.ext.auth.mongo.HashAlgorithm)
   */
  @Override
  public MongoAuth setHashAlgorithm(HashAlgorithm hashAlgorithm) {
    getHashStrategy().setAlgorithm(hashAlgorithm);
    return this;
  }

  @Override
  public String toString() {
    return String.valueOf(hashStrategy);
  }
}
