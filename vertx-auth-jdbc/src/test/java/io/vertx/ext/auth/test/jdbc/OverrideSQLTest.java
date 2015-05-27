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
public class OverrideSQLTest extends JDBCAuthTest {

  @Override
  public void setUp() throws Exception {
    super.setUp();

    authProvider.setAuthenticationQuery("select pwd, pwd_salt from user2 where user_name = ?")
      .setPermissionsQuery("select perm from perms2 where username = ?");
  }
}
