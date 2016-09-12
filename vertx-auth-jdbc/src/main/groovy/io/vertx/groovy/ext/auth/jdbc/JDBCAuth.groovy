/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.groovy.ext.auth.jdbc;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.core.json.JsonObject
import io.vertx.groovy.ext.auth.User
import io.vertx.groovy.ext.jdbc.JDBCClient
import io.vertx.core.json.JsonObject
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating {@link io.vertx.groovy.ext.auth.AuthProvider} instances that use the Vert.x JDBC client
*/
@CompileStatic
public class JDBCAuth extends AuthProvider {
  private final def io.vertx.ext.auth.jdbc.JDBCAuth delegate;
  public JDBCAuth(Object delegate) {
    super((io.vertx.ext.auth.jdbc.JDBCAuth) delegate);
    this.delegate = (io.vertx.ext.auth.jdbc.JDBCAuth) delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Create a JDBC auth provider implementation
   * @param client the JDBC client instance
   * @return the auth provider
   */
  public static JDBCAuth create(JDBCClient client) {
    def ret = InternalHelper.safeCreate(io.vertx.ext.auth.jdbc.JDBCAuth.create(client != null ? (io.vertx.ext.jdbc.JDBCClient)client.getDelegate() : null), io.vertx.groovy.ext.auth.jdbc.JDBCAuth.class);
    return ret;
  }
  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   * @param authenticationQuery the authentication query
   * @return a reference to this for fluency
   */
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) {
    def ret = InternalHelper.safeCreate(delegate.setAuthenticationQuery(authenticationQuery), io.vertx.groovy.ext.auth.jdbc.JDBCAuth.class);
    return ret;
  }
  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   * @param rolesQuery the roles query
   * @return a reference to this for fluency
   */
  public JDBCAuth setRolesQuery(String rolesQuery) {
    def ret = InternalHelper.safeCreate(delegate.setRolesQuery(rolesQuery), io.vertx.groovy.ext.auth.jdbc.JDBCAuth.class);
    return ret;
  }
  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery the permissions query
   * @return a reference to this for fluency
   */
  public JDBCAuth setPermissionsQuery(String permissionsQuery) {
    def ret = InternalHelper.safeCreate(delegate.setPermissionsQuery(permissionsQuery), io.vertx.groovy.ext.auth.jdbc.JDBCAuth.class);
    return ret;
  }
  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  public JDBCAuth setRolePrefix(String rolePrefix) {
    def ret = InternalHelper.safeCreate(delegate.setRolePrefix(rolePrefix), io.vertx.groovy.ext.auth.jdbc.JDBCAuth.class);
    return ret;
  }
}
