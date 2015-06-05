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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.AuthenticationException;
import io.vertx.ext.auth.mongo.HashStrategy;
import io.vertx.ext.auth.mongo.HashStrategy.SaltStyle;
import io.vertx.ext.auth.mongo.MongoAuth;
import io.vertx.ext.auth.mongo.UserFactory;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.ext.mongo.MongoService;

import java.util.List;

/**
 * An implementation of {@link MongoAuth}
 * 
 * @author mremme
 */
public class MongoAuthImpl implements MongoAuth {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthImpl.class);

  private final Vertx vertx;
  private MongoClient mongoClient;
  private String usernameField = DEFAULT_USERNAME_FIELD;
  private String passwordField = DEFAULT_PASSWORD_FIELD;
  private String roleField = DEFAULT_ROLE_FIELD;
  private String permissionField = DEFAULT_PERMISSION_FIELD;
  private String usernameCredentialField = DEFAULT_CREDENTIAL_USERNAME_FIELD;
  private String passwordCredentialField = DEFAULT_CREDENTIAL_PASSWORD_FIELD;
  private String saltField = DEFAULT_SALT_FIELD;
  private String collectionName = DEFAULT_COLLECTION_NAME;

  private JsonObject config;
  private UserFactory userFactory;

  private HashStrategy hashStrategy;

  /**
   * 
   */
  public MongoAuthImpl(Vertx vertx, String serviceName, JsonObject config, UserFactory userFactory) {
    this(vertx, MongoService.createEventBusProxy(vertx, serviceName), config, userFactory);
  }

  /**
   * 
   */
  public MongoAuthImpl(Vertx vertx, MongoClient mongoClient, JsonObject config, UserFactory userFactory) {
    this.vertx = vertx;
    this.mongoClient = mongoClient;
    this.config = config;
    this.userFactory = userFactory;
    init();
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    String username = authInfo.getString(this.usernameCredentialField);
    String password = authInfo.getString(this.passwordCredentialField);

    // Null username is invalid
    if (username == null) {
      resultHandler.handle((Future.failedFuture("Username must be set for authentication.")));
      return;
    }
    if (password == null) {
      resultHandler.handle((Future.failedFuture("Password must be set for authentication.")));
      return;
    }
    AuthToken token = new AuthToken(username, password);

    JsonObject query = createQuery(username);
    mongoClient.find(this.collectionName, query, res -> {

      try {
        if (res.succeeded()) {
          User user = handleSelection(res, token);
          resultHandler.handle(Future.succeededFuture(user));
        } else {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      } catch (Throwable e) {
        log.warn(e);
        resultHandler.handle(Future.failedFuture(e));
      }

    });

  }

  /**
   * The default implementation uses the usernameField as search field
   * 
   * @param username
   * @return
   */
  protected JsonObject createQuery(String username) {
    return new JsonObject().put(usernameField, username);
  }

  /**
   * Examine the selection of found users and return one, if password is fitting,
   * 
   * @param resultList
   * @param username
   * @return
   */
  private User handleSelection(AsyncResult<List<JsonObject>> resultList, AuthToken authToken)
      throws AuthenticationException {
    switch (resultList.result().size()) {
    case 0: {
      String message = "No account found for user [" + authToken.username + "]";
      //log.warn(message);
      throw new AuthenticationException(message);
    }
    case 1: {
      JsonObject json = resultList.result().get(0);
      User user = getUserFactory().createUser(json, this);
      if (examinePassword(user, authToken))
        return user;
      else {
        String message = "Invalid username/password [" + authToken.username + "]";
        //log.warn(message);
        throw new AuthenticationException(message);
      }
    }
    default: {
      // More than one row returned!
      String message = "More than one user row found for user [" + authToken.username + "( "
          + resultList.result().size() + " )]. Usernames must be unique.";
      //log.warn(message);
      throw new AuthenticationException(message);
    }
    }
  }

  /**
   * Examine the given user object. Returns true, if object fits the given authentication
   * 
   * @param userObject
   * @param authToken
   * @return
   */
  private boolean examinePassword(User user, AuthToken authToken) {
    String storedPassword = getHashStrategy().getStoredPwd(user);
    String givenPassword = getHashStrategy().computeHash(authToken.password, user);
    return storedPassword != null && storedPassword.equals(givenPassword);
  }

  /**
   * Initializes the current provider by using the defined config object
   * 
   * @param config
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
    if (roleField != null) {
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
      getHashStrategy().setSaltStyle(SaltStyle.valueOf(saltstyle));
    }

  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setCollectionName(java.lang.String)
   */
  @Override
  public MongoAuth setCollectionName(String collectionName) {
    this.collectionName = collectionName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setUsernameField(java.lang.String)
   */
  @Override
  public MongoAuth setUsernameField(String fieldName) {
    this.usernameField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setPasswordField(java.lang.String)
   */
  @Override
  public MongoAuth setPasswordField(String fieldName) {
    this.passwordField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setRoleField(java.lang.String)
   */
  @Override
  public MongoAuth setRoleField(String fieldName) {
    this.roleField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setUsernameCredentialField(java.lang.String)
   */
  @Override
  public MongoAuth setUsernameCredentialField(String fieldName) {
    this.usernameCredentialField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setPasswordCredentialField(java.lang.String)
   */
  @Override
  public MongoAuth setPasswordCredentialField(String fieldName) {
    this.passwordCredentialField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setSaltField(java.lang.String)
   */
  @Override
  public MongoAuth setSaltField(String fieldName) {
    this.saltField = fieldName;
    return this;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getCollectionName()
   */
  @Override
  public String getCollectionName() {
    return collectionName;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getUsernameField()
   */
  @Override
  public final String getUsernameField() {
    return usernameField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getPasswordField()
   */
  @Override
  public final String getPasswordField() {
    return passwordField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getRoleField()
   */
  @Override
  public final String getRoleField() {
    return roleField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getUsernameCredentialField()
   */
  @Override
  public final String getUsernameCredentialField() {
    return usernameCredentialField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getPasswordCredentialField()
   */
  @Override
  public final String getPasswordCredentialField() {
    return passwordCredentialField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getSaltField()
   */
  @Override
  public final String getSaltField() {
    return saltField;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#getUserFactory()
   */
  @Override
  public UserFactory getUserFactory() {
    if (userFactory == null)
      userFactory = new MongoUserFactory();
    return userFactory;
  }

  /* (non-Javadoc)
   * @see io.vertx.ext.auth.mongo.MongoAuth#setUserFactory(io.vertx.ext.auth.mongo.UserFactory)
   */
  @Override
  public MongoAuth setUserFactory(UserFactory userFactory) {
    this.userFactory = userFactory;
    return this;
  }

  @Override
  public MongoAuth setPermissionField(String fieldName) {
    this.permissionField = fieldName;
    return this;
  }

  @Override
  public String getPermissionField() {
    return this.permissionField;
  }

  @Override
  public MongoAuth setHashStrategy(HashStrategy hashStrategy) {
    this.hashStrategy = hashStrategy;
    return this;
  }

  @Override
  public HashStrategy getHashStrategy() {
    if (hashStrategy == null)
      hashStrategy = new DefaultHashStrategy();
    return hashStrategy;
  }

  /**
   * The incoming data from an authentication request
   * 
   * @author mremme
   */
  class AuthToken {
    String username;
    String password;

    AuthToken(String username, String password) {
      this.username = username;
      this.password = password;
    }
  }

  @Override
  public String toString() {
    return String.valueOf(hashStrategy);
  }
}
