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

import java.sql.Connection;
import java.sql.DriverManager;

import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import org.junit.BeforeClass;
import org.junit.Test;

import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.jdbc.JDBCAuthorization;
import io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthorizationProviderTest extends JDBCAuthenticationProviderTest {

  static {
    SQL.add("drop table if exists user_roles;");
    SQL.add("drop table if exists roles_perms;");
    SQL.add("create table user_roles (username varchar(255), role varchar(255));");
    SQL.add("create table roles_perms (role varchar(255), perm varchar(255));");

    SQL.add("ALTER TABLE user_roles ADD CONSTRAINT pk_user_roles PRIMARY KEY (username, role);");
    SQL.add("ALTER TABLE roles_perms ADD CONSTRAINT pk_roles_perms PRIMARY KEY (role, perm);");

    SQL.add("insert into roles_perms values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms values ('admin', 'merge_pr');");
    SQL.add("insert into user_roles values ('tim', 'dev');");
    SQL.add("insert into user_roles values ('tim', 'admin');");

    // and a second set of tables with slight differences
    SQL.add("drop table if exists user_roles2;");
    SQL.add("drop table if exists roles_perms2;");
    SQL.add("create table user_roles2 (user_name varchar(255), role varchar(255));");
    SQL.add("create table roles_perms2 (role varchar(255), perm varchar(255));");

    SQL.add("insert into roles_perms2 values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms2 values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms2 values ('admin', 'merge_pr');");
    SQL.add("insert into user_roles2 values ('tim', 'dev');");
    SQL.add("insert into user_roles2 values ('tim', 'admin');");
  }

  private JDBCAuthorization authorizationProvider;
  private JDBCAuthorizationOptions authorizationOptions;

  @BeforeClass
  public static void createDb() throws Exception {
    Connection conn = DriverManager.getConnection(config().getString("url"));
    for (String sql : SQL) {
      System.out.println("Executing: " + sql);
      conn.createStatement().execute(sql);
    }
  }

  protected JDBCAuthorizationOptions getAuthorizationOptions() {
    if (authorizationOptions == null) {
      authorizationOptions = new JDBCAuthorizationOptions();
    }
    return authorizationOptions;
  }

  protected JDBCAuthorization getAuthorizationProvider() {
    if (authorizationProvider == null) {
      authorizationProvider = JDBCAuthorization.create("id", getJDBCCLient(), new JDBCAuthorizationOptions());
    }
    return authorizationProvider;
  }

  @Test
  public void testAuthoriseHasRole(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    getAuthenticationProvider()
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        getAuthorizationProvider()
          .getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertTrue(RoleBasedAuthorization.create("dev").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasRole(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    getAuthenticationProvider()
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        getAuthorizationProvider()
          .getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertFalse(RoleBasedAuthorization.create("manager").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseHasPermission(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    getAuthenticationProvider()
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        getAuthorizationProvider()
          .getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertTrue(PermissionBasedAuthorization.create("commit_code").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasPermission(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    getAuthenticationProvider()
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        getAuthorizationProvider()
          .getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertFalse(PermissionBasedAuthorization.create("eat_sandwich").match(user));
            test.complete();
          });
      });
  }
}
