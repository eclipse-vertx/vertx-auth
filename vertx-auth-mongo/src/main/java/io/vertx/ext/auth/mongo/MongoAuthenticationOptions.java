/*
 * Copyright 2015 Red Hat, Inc.
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

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.mongo.MongoClient;

/**
 * Options configuring Mongo authentication.
 *
 * @author francoisprunier
 *
 */
@DataObject(generateConverter = true)
public class MongoAuthenticationOptions {

  private boolean shared;
  private String datasourceName;
  private String collectionName;
  private String usernameField;
  private String passwordField;
  private String usernameCredentialField;
  private String passwordCredentialField;
  private String saltField;
  private HashSaltStyle saltStyle;
  private HashAlgorithm hashAlgorithm;
  private JsonObject config;

  public MongoAuthenticationOptions() {
    shared = false;
    datasourceName = null;
    collectionName = MongoAuthentication.DEFAULT_COLLECTION_NAME;
    usernameField = MongoAuthentication.DEFAULT_USERNAME_FIELD;
    passwordField = MongoAuthentication.DEFAULT_PASSWORD_FIELD;
    usernameCredentialField = MongoAuthentication.DEFAULT_CREDENTIAL_USERNAME_FIELD;
    passwordCredentialField = MongoAuthentication.DEFAULT_CREDENTIAL_PASSWORD_FIELD;
    saltField = MongoAuthentication.DEFAULT_SALT_FIELD;
    saltStyle = null;
  }

  public MongoAuthenticationOptions(JsonObject json) {
    this();
    MongoAuthenticationOptionsConverter.fromJson(json, this);
  }

  public boolean getShared() {
    return shared;
  }

  /**
   * Use a shared Mongo client or not.
   *
   * @param shared true to use a shared client
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setShared(boolean shared) {
    this.shared = shared;
    return this;
  }

  public String getDatasourceName() {
    return datasourceName;
  }

  /**
   * The mongo data source name: see Mongo Client documentation.
   *
   * @param datasourceName the data source name
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setDatasourceName(String datasourceName) {
    this.datasourceName = datasourceName;
    return this;
  }

  public JsonObject getConfig() {
    return config;
  }

  /**
   * The mongo client configuration: see Mongo Client documentation.
   *
   * @param config the mongo config
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setConfig(JsonObject config) {
    this.config = config;
    return this;
  }

  public String getCollectionName() {
    return collectionName;
  }

  /**
   * The property name to be used to set the name of the collection inside the config.
   *
   * @param collectionName the collection name
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setCollectionName(String collectionName) {
    this.collectionName = collectionName;
    return this;
  }

  public String getUsernameField() {
    return usernameField;
  }

  /**
   * The property name to be used to set the name of the field, where the username is stored inside.
   *
   * @param usernameField the username field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setUsernameField(String usernameField) {
    this.usernameField = usernameField;
    return this;
  }

  public String getPasswordField() {
    return passwordField;
  }

  /**
   * The property name to be used to set the name of the field, where the password is stored inside
   *
   * @param passwordField the password field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setPasswordField(String passwordField) {
    this.passwordField = passwordField;
    return this;
  }

  public String getUsernameCredentialField() {
    return usernameCredentialField;
  }

  /**
   * The property name to be used to set the name of the field, where the username for the credentials is stored inside.
   *
   * @param usernameCredentialField the username credential field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setUsernameCredentialField(String usernameCredentialField) {
    this.usernameCredentialField = usernameCredentialField;
    return this;
  }

  public String getPasswordCredentialField() {
    return passwordCredentialField;
  }

  public MongoAuthenticationOptions setPasswordCredentialField(String passwordCredentialField) {
    this.passwordCredentialField = passwordCredentialField;
    return this;
  }

  public String getSaltField() {
    return saltField;
  }

  /**
   * The property name to be used to set the name of the field, where the SALT is stored inside.
   *
   * @param saltField the salt field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setSaltField(String saltField) {
    this.saltField = saltField;
    return this;
  }

  public HashSaltStyle getSaltStyle() {
    return saltStyle;
  }

  /**
   * The property name to be used to set the name of the field, where the salt style is stored inside
   *
   * @param saltStyle the salt style
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthenticationOptions setSaltStyle(HashSaltStyle saltStyle) {
    this.saltStyle = saltStyle;
    return this;
  }

  public HashAlgorithm getHashAlgorithm() {
    return hashAlgorithm;
  }

  public MongoAuthenticationOptions setHashAlgorithm(HashAlgorithm hashAlgorithm) {
    this.hashAlgorithm = hashAlgorithm;
    return this;
  }
}
