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
import io.vertx.core.json.JsonObject;

/**
 * Options configuring Mongo authentication.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class MongoAuthOptions {

  private boolean shared;
  private String datasourceName;
  private String collectionName;
  private String usernameField;
  private String passwordField;
  private String roleField;
  private String permissionField;
  private String usernameCredentialField;
  private String saltField;
  private HashSaltStyle saltStyle;
  private JsonObject config;

  public MongoAuthOptions() {
    shared = false;
    datasourceName = null;
    collectionName = MongoAuth.DEFAULT_COLLECTION_NAME;
    usernameField = MongoAuth.DEFAULT_USERNAME_FIELD;
    passwordField = MongoAuth.DEFAULT_PASSWORD_FIELD;
    roleField = MongoAuth.DEFAULT_ROLE_FIELD;
    permissionField = MongoAuth.DEFAULT_PERMISSION_FIELD;
    usernameCredentialField = MongoAuth.DEFAULT_CREDENTIAL_USERNAME_FIELD;
    saltField = MongoAuth.DEFAULT_SALT_FIELD;
    saltStyle = null;
  }

  public MongoAuthOptions(MongoAuthOptions that) {
    shared = that.shared;
    datasourceName = that.datasourceName;
    datasourceName = that.datasourceName;
    collectionName = that.collectionName;
    usernameField = that.usernameField;
    passwordField = that.passwordField;
    roleField = that.roleField;
    permissionField = that.permissionField;
    usernameCredentialField = that.usernameCredentialField;
    saltField = that.saltField;
    saltStyle = that.saltStyle;
    config = that.config != null ? that.config.copy() : null;
  }

  public MongoAuthOptions(JsonObject json) {
    this();
    MongoAuthOptionsConverter.fromJson(json, this);
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
  public MongoAuthOptions setShared(boolean shared) {
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
  public MongoAuthOptions setDatasourceName(String datasourceName) {
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
  public MongoAuthOptions setConfig(JsonObject config) {
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
  public MongoAuthOptions setCollectionName(String collectionName) {
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
  public MongoAuthOptions setUsernameField(String usernameField) {
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
  public MongoAuthOptions setPasswordField(String passwordField) {
    this.passwordField = passwordField;
    return this;
  }

  public String getRoleField() {
    return roleField;
  }

  /**
   * The property name to be used to set the name of the field, where the roles are stored inside.
   *
   * @param roleField the role field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthOptions setRoleField(String roleField) {
    this.roleField = roleField;
    return this;
  }

  public String getPermissionField() {
    return permissionField;
  }

  /**
   * The property name to be used to set the name of the field, where the permissions are stored inside.
   *
   * @param permissionField the permission field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthOptions setPermissionField(String permissionField) {
    this.permissionField = permissionField;
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
  public MongoAuthOptions setUsernameCredentialField(String usernameCredentialField) {
    this.usernameCredentialField = usernameCredentialField;
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
  public MongoAuthOptions setSaltField(String saltField) {
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
  public MongoAuthOptions setSaltStyle(HashSaltStyle saltStyle) {
    this.saltStyle = saltStyle;
    return this;
  }
}
