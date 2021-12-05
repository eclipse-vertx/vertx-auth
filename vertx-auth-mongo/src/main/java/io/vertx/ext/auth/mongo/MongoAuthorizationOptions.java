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
  private String roleCollectionName;
  private String roleNameField;
  private String rolePermissionField;
  private boolean readRolePermissions;

  public MongoAuthorizationOptions() {
    collectionName = MongoAuthorization.DEFAULT_COLLECTION_NAME;
    usernameField = MongoAuthorization.DEFAULT_USERNAME_FIELD;
    roleField = MongoAuthorization.DEFAULT_ROLE_FIELD;
    permissionField = MongoAuthorization.DEFAULT_PERMISSION_FIELD;
    roleCollectionName = MongoAuthorization.DEFAULT_ROLES_COLLECTION_NAME;
    roleNameField = MongoAuthorization.DEFAULT_ROLENAME_FIELD;
    rolePermissionField = MongoAuthorization.DEFAULT_ROLE_PERMISSION_FIELD;
    readRolePermissions = MongoAuthorization.DEFAULT_READ_ROLE_PERMISSIONS;
  }

  public MongoAuthorizationOptions(JsonObject json) {
    this();
    MongoAuthorizationOptionsConverter.fromJson(json, this);
  }

  public String getCollectionName() {
    return collectionName;
  }

  /**
   * Set the name of the MongoDB collection containing user authorizations.
   * Per default configuration, that collection is called <code>authorizations</code> and is expected to contain objects having the following fields:
   * <ul>
   *     <li><code>username</code>: field name can be overridden with {@link #setUsernameField(String) setUsernameField} </li>
   *     <li><code>permissions</code>: field name can be overridden with {@link #setPermissionField(String) setPermissionField} </li>
   *     <li><code>roles</code>: field name can be overridden with {@link #setRoleField(String) setPermissionField} </li>
   * </ul>
   *
   * @param collectionName the collection name
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setCollectionName(String collectionName) {
    this.collectionName = collectionName;
    return this;
  }

  public String getRoleCollectionName() {
    return roleCollectionName;
  }

  /**
   * Set the name of the MongoDB collection containing role definitions.
   * Per default configuration, that collection is called <code>roles</code> and is expected to contain objects having the following properties:
   * <ul>
   *     <li><code>rolename</code>: can be overridden with {@link #setRoleNameField(String) setRoleNameField} </li>
   *     <li><code>permissions</code>: can be overridden with {@link #setRolePermissionField(String) setRolePermissionField} </li>
   * </ul>
   *
   * @param roleCollectionName the collection name
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setRoleCollectionName(String roleCollectionName) {
    this.roleCollectionName = roleCollectionName;
    return this;
  }

  public String getUsernameField() {
    return usernameField;
  }

  /**
   * Set the name of field containing the username in the collection of user authorizations.
   * The default value is <code>username</code>.
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
   * Set the name of field containing user roles in the collection of user authorizations.
   * The default value is <code>roles</code>.
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
   * Set the name of field containing user permissions in the collection of user authorizations.
   * The default value is <code>permissions</code>.
   *
   * @param permissionField the permission field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setPermissionField(String permissionField) {
    this.permissionField = permissionField;
    return this;
  }

  public String getRoleNameField() {
    return roleNameField;
  }

  /**
   * Set the name of field containing the name of the role in the collection of role definitions.
   * The default value is <code>rolename</code>.
   *
   * @param roleNameField the role name field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setRoleNameField(String roleNameField) {
    this.roleNameField = roleNameField;
    return this;
  }

  public String getRolePermissionField() {
    return rolePermissionField;
  }

  /**
   * Set the name of field containing role permissions in the collection of role definitions.
   * The default value is <code>permissions</code>.
   *
   * @param rolePermissionField the permission field
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setRolePermissionField(String rolePermissionField) {
    this.rolePermissionField = rolePermissionField;
    return this;
  }

  public boolean isReadRolePermissions() {
    return readRolePermissions;
  }

  /**
   * Enable or disable the behavior consisting in reading role definitions from another collection to get permissions attached to roles.
   * The default value is <code>false</code>.
   *
   * @param readRolePermissions true to enable, false to disable the behavior
   * @return a reference to this, so the API can be used fluently
   */
  public MongoAuthorizationOptions setReadRolePermissions(boolean readRolePermissions) {
    this.readRolePermissions = readRolePermissions;
    return this;
  }

}
