/*
 * Copyright 2014 Red Hat, Inc.
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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.AuthorizationProvider;
import io.vertx.ext.auth.jdbc.impl.JDBCAuthorizationImpl;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Factory interface for creating {@link io.vertx.ext.auth.AuthorizationProvider} instances that use the Vert.x JDBC client.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface JDBCAuthorization extends AuthorizationProvider {

  /**
   * Create a JDBC authorization provider implementation
   *
<<<<<<< HEAD
<<<<<<< HEAD:vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/JDBCAuthorizationProvider.java
   * @param providerId  the provider id
   * @param client  the JDBC client instance
   * @param options  the {@link JDBCAuthorizationOptions}
   * @return  the auth provider
   */
  static JDBCAuthorizationProvider create(String providerId, JDBCClient client, JDBCAuthorizationOptions options) {
    return new JDBCAuthorizationProviderImpl(providerId, client, options);
  }

=======
   * @param client the JDBC client instance
   * @return  the auth provider
   */
  static JDBCAuthorization create(JDBCClient client) {
    return new JDBCAuthorizationImpl(client);
  }

  /**
   * Create a JDBC authorization provider implementation
   *
=======
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
   * @param options JDBCAuthorizationOptions
   * @return  the auth provider
   */
  static JDBCAuthorization create(JDBCClient client, JDBCAuthorizationOptions options) {
    return new JDBCAuthorizationImpl(client, options);
  }

<<<<<<< HEAD
  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   * @param rolesQuery  the roles query
   * @return  a reference to this for fluency
   */
  @Fluent
  JDBCAuthorization setRolesQuery(String rolesQuery);

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery  the permissions query
   * @return  a reference to this for fluency
   */
  @Fluent
  JDBCAuthorization setPermissionsQuery(String permissionsQuery);

>>>>>>> updated code based on comments from Paulo::vertx-auth-jdbc/src/main/java/io/vertx/ext/auth/jdbc/JDBCAuthorization.java
=======
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
}
