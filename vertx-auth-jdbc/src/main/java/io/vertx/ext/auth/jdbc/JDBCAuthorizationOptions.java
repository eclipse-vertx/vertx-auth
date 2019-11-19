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
package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.DataObject;
<<<<<<< HEAD
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Options configuring JDBC authentication.
=======
import io.vertx.core.json.JsonObject;

/**
 * Options configuring JDBC authorization
>>>>>>> updated code based on comments from Paulo:
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class JDBCAuthorizationOptions {

<<<<<<< HEAD
  /**
   * The default query to retrieve all roles for the user
   */
  private final static String DEFAULT_ROLES_QUERY = "SELECT ROLE FROM USER_ROLES WHERE USERNAME = ?";

  /**
   * The default query to retrieve all permissions for the role
   */
  private final static String DEFAULT_PERMISSIONS_QUERY = "SELECT PERM FROM ROLES_PERMS RP, USER_ROLES UR WHERE UR.USERNAME = ? AND UR.ROLE = RP.ROLE";

=======
  private boolean shared;
  private String datasourceName;
>>>>>>> updated code based on comments from Paulo:
  private String rolesQuery;
  private String permissionsQuery;

  public JDBCAuthorizationOptions() {
<<<<<<< HEAD
    this.rolesQuery = DEFAULT_ROLES_QUERY;
    this.permissionsQuery = DEFAULT_PERMISSIONS_QUERY;
=======
    this.shared = true;
>>>>>>> updated code based on comments from Paulo:
  }

  public JDBCAuthorizationOptions(JsonObject json) {
    this();
    JDBCAuthorizationOptionsConverter.fromJson(json, this);
  }

<<<<<<< HEAD
=======
  public boolean isShared() {
    return shared;
  }

  /**
   * Set whether the JDBC client is shared or non shared.
   *
   * @param shared the sharing mode
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthorizationOptions setShared(boolean shared) {
    this.shared = shared;
    return this;
  }

  public String getDatasourceName() {
    return datasourceName;
  }

  /**
   * Set the data source name to use, only use in shared mode.
   *
   * @param datasourceName the data source name
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthorizationOptions setDatasourceName(String datasourceName) {
    this.datasourceName = datasourceName;
    return this;
  }

>>>>>>> updated code based on comments from Paulo:
  public String getRolesQuery() {
    return rolesQuery;
  }

  /**
<<<<<<< HEAD
   * Set the roles query to use. Use this if you want to override the default roles query.
=======
   * Set the roles query to use. Use this if you want to override the default
   * roles query.
>>>>>>> updated code based on comments from Paulo:
   *
   * @param rolesQuery the roles query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthorizationOptions setRolesQuery(String rolesQuery) {
    this.rolesQuery = rolesQuery;
    return this;
  }

  public String getPermissionsQuery() {
    return permissionsQuery;
  }

  /**
<<<<<<< HEAD
   * Set the permissions query to use. Use this if you want to override the default permissions query.
=======
   * Set the permissions query to use. Use this if you want to override the
   * default permissions query.
>>>>>>> updated code based on comments from Paulo:
   *
   * @param permissionsQuery the permissions query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthorizationOptions setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }

}
