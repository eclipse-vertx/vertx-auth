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
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.sql.impl.SqlAuthorizationImpl;
import io.vertx.sqlclient.SqlClient;

/**
 * Factory interface for creating {@link AuthorizationProvider} instances that use the Vert.x SQL client.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface SqlAuthorization extends AuthorizationProvider {

  /**
   * Create a JDBC authorization provider implementation
   *
   * @param client  the SQL client instance
   * @return  the auth provider
   */
  static SqlAuthorization create(SqlClient client) {
    return create(client, new SqlAuthorizationOptions());
  }

  /**
   * Create a JDBC authorization provider implementation
   *
   * @param client  the SQL client instance
   * @param options  the {@link SqlAuthorizationOptions}
   * @return  the auth provider
   */
  static SqlAuthorization create(SqlClient client, SqlAuthorizationOptions options) {
    return new SqlAuthorizationImpl(client, options);
  }
}
