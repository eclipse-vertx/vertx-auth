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
 * @author francoisprunier
 *
 */
@DataObject(generateConverter = true)
public class MongoAuthorizationOptions {

  private String collectionName;
  private String usernameField;
  private String roleField;
  private String permissionField;

  public MongoAuthorizationOptions() {
    collectionName = MongoAuthorization.DEFAULT_COLLECTION_NAME;
    usernameField = MongoAuthorization.DEFAULT_USERNAME_FIELD;
    roleField = MongoAuthorization.DEFAULT_ROLE_FIELD;
    permissionField = MongoAuthorization.DEFAULT_PERMISSION_FIELD;
  }

  public MongoAuthorizationOptions(JsonObject json) {
    this();
    MongoAuthorizationOptionsConverter.fromJson(json, this);
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
  public MongoAuthorizationOptions setCollectionName(String collectionName) {
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
  public MongoAuthorizationOptions setUsernameField(String usernameField) {
    this.usernameField = usernameField;
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
  public MongoAuthorizationOptions setRoleField(String roleField) {
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
  public MongoAuthorizationOptions setPermissionField(String permissionField) {
    this.permissionField = permissionField;
    return this;
  }
}
