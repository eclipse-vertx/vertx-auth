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
import io.vertx.groovy.ext.jdbc.JDBCClient
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating {@link io.vertx.groovy.ext.auth.AuthProvider} instances that use the Vert.x JDBC client
*/
@CompileStatic
public class JDBCAuth extends AuthProvider {
  final def io.vertx.ext.auth.jdbc.JDBCAuth delegate;
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
    def ret= new io.vertx.groovy.ext.auth.jdbc.JDBCAuth(io.vertx.ext.auth.jdbc.JDBCAuth.create((io.vertx.ext.jdbc.JDBCClient)client.getDelegate()));
    return ret;
  }
  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   * @param authenticationQuery the authentication query
   * @return a reference to this for fluency
   */
  public JDBCAuth setAuthenticationQuery(String authenticationQuery) {
    def ret= new io.vertx.groovy.ext.auth.jdbc.JDBCAuth(this.delegate.setAuthenticationQuery(authenticationQuery));
    return ret;
  }
  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery the permissions query
   * @return a reference to this for fluency
   */
  public JDBCAuth setPermissionsQuery(String permissionsQuery) {
    def ret= new io.vertx.groovy.ext.auth.jdbc.JDBCAuth(this.delegate.setPermissionsQuery(permissionsQuery));
    return ret;
  }
}
