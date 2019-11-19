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
import io.vertx.core.json.JsonObject;

/**
 * Options configuring JDBC authorization
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class JDBCAuthorizationOptions {

  private boolean shared;
  private String datasourceName;
  private String rolesQuery;
  private String permissionsQuery;

  public JDBCAuthorizationOptions() {
    this.shared = true;
  }

  public JDBCAuthorizationOptions(JsonObject json) {
    this();
    JDBCAuthorizationOptionsConverter.fromJson(json, this);
  }

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

  public String getRolesQuery() {
    return rolesQuery;
  }

  /**
   * Set the roles query to use. Use this if you want to override the default
   * roles query.
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
   * Set the permissions query to use. Use this if you want to override the
   * default permissions query.
   *
   * @param permissionsQuery the permissions query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthorizationOptions setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }

}
