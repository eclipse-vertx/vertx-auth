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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.jdbc.impl.JDBCAuthImpl;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Factory interface for creating {@link io.vertx.ext.auth.AuthProvider} instances that use the Vert.x JDBC client.
 *
 * By default the hashing strategy is SHA-512. If you're already running in production this is backwards
 * compatible, however for new deployments or security upgrades it is recommended to use the PBKDF2 strategy
 * as it is the current OWASP recommendation for password storage.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface JDBCAuth extends AuthProvider {

  /**
   * The default query to be used for authentication
   */
  String DEFAULT_AUTHENTICATE_QUERY = "SELECT PASSWORD, PASSWORD_SALT FROM USER WHERE USERNAME = ?";

  /**
   * The default query to retrieve all roles for the user
   */
  String DEFAULT_ROLES_QUERY = "SELECT ROLE FROM USER_ROLES WHERE USERNAME = ?";

  /**
   * The default query to retrieve all permissions for the role
   */
  String DEFAULT_PERMISSIONS_QUERY = "SELECT PERM FROM ROLES_PERMS RP, USER_ROLES UR WHERE UR.USERNAME = ? AND UR.ROLE = RP.ROLE";

  /**
   * The default role prefix
   */
  String DEFAULT_ROLE_PREFIX = "role:";

  /**
   * Create a JDBC auth provider implementation
   *
   * @param client  the JDBC client instance
   * @return  the auth provider
   */
  static JDBCAuth create(Vertx vertx, JDBCClient client) {
    return new JDBCAuthImpl(vertx, client);
  }

  /**
   * Set the authentication query to use. Use this if you want to override the default authentication query.
   * @param authenticationQuery  the authentication query
   * @return  a reference to this for fluency
   */
  @Fluent
  JDBCAuth setAuthenticationQuery(String authenticationQuery);

  /**
   * Set the roles query to use. Use this if you want to override the default roles query.
   * @param rolesQuery  the roles query
   * @return  a reference to this for fluency
   */
  @Fluent
  JDBCAuth setRolesQuery(String rolesQuery);

  /**
   * Set the permissions query to use. Use this if you want to override the default permissions query.
   * @param permissionsQuery  the permissions query
   * @return  a reference to this for fluency
   */
  @Fluent
  JDBCAuth setPermissionsQuery(String permissionsQuery);

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  @Fluent
  JDBCAuth setRolePrefix(String rolePrefix);

  /**
   * Set the hash strategy to use. Use this if you want override the default hash strategy
   * @param strategy  the strategy
   * @return a reference to this for fluency
   */
  @GenIgnore
  JDBCAuth setHashStrategy(JDBCHashStrategy strategy);

  /**
   * Compute the hashed password given the unhashed password and the salt without nonce
   *
   * The implementation relays to the JDBCHashStrategy provided.
   *
   * @param password  the unhashed password
   * @param salt  the salt
   * @return  the hashed password
   */
  default String computeHash(String password, String salt) {
    return computeHash(password, salt, -1);
  }

  /**
   * Compute the hashed password given the unhashed password and the salt
   *
   * The implementation relays to the JDBCHashStrategy provided.
   *
   * @param password  the unhashed password
   * @param salt  the salt
   * @param version the nonce version to use
   * @return  the hashed password
   */
  String computeHash(String password, String salt, int version);

  /**
   * Compute a salt string.
   *
   * The implementation relays to the JDBCHashStrategy provided.
   *
   * @return a non null salt value
   */
  String generateSalt();

  /**
   * Provide a application configuration level on hash nonce's as a ordered list of
   * nonces where each position corresponds to a version.
   *
   * The nonces are supposed not to be stored in the underlying jdbc storage but to
   * be provided as a application configuration. The idea is to add one extra variable
   * to the hash function in order to make breaking the passwords using rainbow tables
   * or precomputed hashes harder. Leaving the attacker only with the brute force
   * approach.
   *
   * The implementation relays to the JDBCHashStrategy provided.
   *
   * @param nonces a List of non null Strings.
   * @return a reference to this for fluency
   */
  @Fluent
  JDBCAuth setNonces(JsonArray nonces);
}
