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
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Options configuring JDBC authentication.
 * @deprecated This class has been replaced by the class {@link io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions} for authentication and {@link io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions} for authorization
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
@Deprecated
public class JDBCAuthOptions implements io.vertx.ext.auth.AuthOptions {

  private boolean shared;
  private String datasourceName;
  private String authenticationQuery;
  private String rolesQuery;
  private String permissionsQuery;
  private String rolesPrefix;
  private JsonObject config;

  public JDBCAuthOptions() {
    this.shared = true;
    this.config = null;
  }

  public JDBCAuthOptions(JDBCAuthOptions that) {
    shared = that.shared;
    datasourceName = that.datasourceName;
    config = that.config != null ? that.config.copy() : null;
  }

  public JDBCAuthOptions(JsonObject json) {
    this();
    JDBCAuthOptionsConverter.fromJson(json, this);
  }

  @Override
  public JDBCAuthOptions clone() {
    return new JDBCAuthOptions(this);
  }

  @Override
  public JDBCAuth createProvider(Vertx vertx) {
    JDBCClient client;
    if (shared) {
      if (datasourceName != null) {
        client = JDBCClient.createShared(vertx, config, datasourceName);
      } else {
        client = JDBCClient.createShared(vertx, config);
      }
    } else {
      client = JDBCClient.create(vertx, config);
    }
    JDBCAuth auth = JDBCAuth.create(vertx, client);
    if (authenticationQuery != null) {
      auth.setAuthenticationQuery(authenticationQuery);
    }
    if (rolesQuery != null) {
      auth.setRolesQuery(rolesQuery);
    }
    if (permissionsQuery != null) {
      auth.setPermissionsQuery(permissionsQuery);
    }
    if (rolesPrefix != null) {
      auth.setRolePrefix(rolesPrefix);
    }
    return auth;
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
  public JDBCAuthOptions setShared(boolean shared) {
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
  public JDBCAuthOptions setDatasourceName(String datasourceName) {
    this.datasourceName = datasourceName;
    return this;
  }

  public JsonObject getConfig() {
    return config;
  }

  /**
   * The configuration of the JDBC client: refer to the Vert.x JDBC Client configuration.
   *
   * @param config
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setConfig(JsonObject config) {
    this.config = config;
    return this;
  }

  public String getAuthenticationQuery() {
    return authenticationQuery;
  }

  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   *
   * @param authenticationQuery the authentication query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
    return this;
  }

  public String getRolesQuery() {
    return rolesQuery;
  }

  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   *
   * @param rolesQuery the roles query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setRolesQuery(String rolesQuery) {
    this.rolesQuery = rolesQuery;
    return this;
  }

  public String getPermissionsQuery() {
    return permissionsQuery;
  }

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   *
   * @param permissionsQuery the permissions query
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setPermissionsQuery(String permissionsQuery) {
    this.permissionsQuery = permissionsQuery;
    return this;
  }

  public String getRolesPrefix() {
    return rolesPrefix;
  }

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   *
   * @param rolesPrefix roles prefix
   * @return a reference to this, so the API can be used fluently
   */
  public JDBCAuthOptions setRolesPrefix(String rolesPrefix) {
    this.rolesPrefix = rolesPrefix;
    return this;
  }
}
