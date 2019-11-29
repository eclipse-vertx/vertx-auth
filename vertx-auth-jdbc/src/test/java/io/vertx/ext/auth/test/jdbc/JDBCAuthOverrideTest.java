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

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthOverrideTest extends JDBCAuthTest {

  static final String AUTHENTICATION_QUERY_OVERRIDE = "select pwd, pwd_salt from user2 where user_name = ?";
  static final String PERMISSIONS_QUERY_OVERRIDE = "select perm from roles_perms2 rp, user_roles2 ur where ur.user_name = ? and ur.role = rp.role";
  static final String ROLES_QUERY_OVERRIDE = "select role from user_roles2 where user_name = ?";

  @Override
  public void setUp() throws Exception {
    super.setUp();

    authProvider.setAuthenticationQuery(AUTHENTICATION_QUERY_OVERRIDE)
      .setPermissionsQuery(PERMISSIONS_QUERY_OVERRIDE)
      .setRolesQuery(ROLES_QUERY_OVERRIDE);
  }
}
