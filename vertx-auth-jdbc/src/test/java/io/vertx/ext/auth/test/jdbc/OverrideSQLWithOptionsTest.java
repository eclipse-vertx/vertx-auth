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

package io.vertx.ext.auth.test.jdbc;

import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.auth.jdbc.JDBCAuthOptions;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class OverrideSQLWithOptionsTest extends JDBCAuthTest {

  @Override
  protected JDBCAuth createProvider() {
    return new JDBCAuthOptions().
        setShared(false).
        setConfig(config()).
        setAuthenticationQuery(OverrideSQLTest.AUTHENTICATION_QUERY_OVERRIDE).
        setPermissionsQuery(OverrideSQLTest.PERMISSIONS_QUERY_OVERRIDE).
        setRolesQuery(OverrideSQLTest.ROLES_QUERY_OVERRIDE).
        createProvider(vertx);
  }
}
