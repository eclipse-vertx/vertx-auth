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

package io.vertx.rxjava.ext.auth.jdbc;

import java.util.Map;
import io.vertx.lang.rxjava.InternalHelper;
import rx.Observable;
import io.vertx.rxjava.ext.jdbc.JDBCClient;
import io.vertx.rxjava.ext.auth.AuthProvider;

/**
 * Factory interface for creating {@link io.vertx.rxjava.ext.auth.AuthProvider} instances that use the Vert.x JDBC client
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuth original} non RX-ified interface using Vert.x codegen.
 */

public class JDBCAuth extends AuthProvider {

  final io.vertx.ext.auth.jdbc.JDBCAuth delegate;

  public JDBCAuth(io.vertx.ext.auth.jdbc.JDBCAuth delegate) {
    super(delegate);
    this.delegate = delegate;
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
    JDBCAuth ret= JDBCAuth.newInstance(io.vertx.ext.auth.jdbc.JDBCAuth.create((io.vertx.ext.jdbc.JDBCClient) client.getDelegate()));
    return ret;
  }

  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   * @param authenticationQuery the authentication query
   * @return a reference to this for fluency
   */
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) { 
    JDBCAuth ret= JDBCAuth.newInstance(this.delegate.setAuthenticationQuery(authenticationQuery));
    return ret;
  }

  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   * @param rolesQuery the roles query
   * @return a reference to this for fluency
   */
  public JDBCAuth setRolesQuery(String rolesQuery) { 
    JDBCAuth ret= JDBCAuth.newInstance(this.delegate.setRolesQuery(rolesQuery));
    return ret;
  }

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery the permissions query
   * @return a reference to this for fluency
   */
  public JDBCAuth setPermissionsQuery(String permissionsQuery) { 
    JDBCAuth ret= JDBCAuth.newInstance(this.delegate.setPermissionsQuery(permissionsQuery));
    return ret;
  }

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  public JDBCAuth setRolePrefix(String rolePrefix) { 
    JDBCAuth ret= JDBCAuth.newInstance(this.delegate.setRolePrefix(rolePrefix));
    return ret;
  }


  public static JDBCAuth newInstance(io.vertx.ext.auth.jdbc.JDBCAuth arg) {
    return new JDBCAuth(arg);
  }
}
