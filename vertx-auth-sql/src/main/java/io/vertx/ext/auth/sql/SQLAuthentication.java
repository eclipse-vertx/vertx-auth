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

package io.vertx.ext.auth.sql;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.sql.impl.SQLAuthenticationImpl;
import io.vertx.sqlclient.SqlClient;

/**
 * Factory interface for creating {@link io.vertx.ext.auth.AuthProvider} instances that use the Vert.x JDBC client.
 *
 * By default the hashing strategy is PBKDF2 which is the current recommended hashing strategy by OWASP
 * for password storage.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface SQLAuthentication extends AuthProvider {

  /**
   * Create a JDBC auth provider implementation
   *
   * @param client  the JDBC client instance
   * @param options authentication options
   * @return  the auth provider
   */
  static SQLAuthentication create(SqlClient client, SQLAuthenticationOptions options) {
    return new SQLAuthenticationImpl(client, options);
  }

}
