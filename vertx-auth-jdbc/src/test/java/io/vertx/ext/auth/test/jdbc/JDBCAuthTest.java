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
import java.util.ArrayList;
import java.util.List;

import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.jdbc.JDBCAuth;
import io.vertx.ext.jdbc.JDBCClient;
import org.junit.runner.RunWith;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@RunWith(VertxUnitRunner.class)
public class JDBCAuthTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  static final List<String> SQL = new ArrayList<>();

  static {
    SQL.add("drop table if exists user;");
    SQL.add("drop table if exists user_roles;");
    SQL.add("drop table if exists roles_perms;");
    SQL.add("create table user (username varchar(255), password varchar(255), password_salt varchar(255) );");
    SQL.add("create table user_roles (username varchar(255), role varchar(255));");
    SQL.add("create table roles_perms (role varchar(255), perm varchar(255));");

    SQL.add("ALTER TABLE user_roles ADD CONSTRAINT pk_user_roles PRIMARY KEY (username, role);");
    SQL.add("ALTER TABLE roles_perms ADD CONSTRAINT pk_roles_perms PRIMARY KEY (role, perm);");

    SQL.add("insert into user values ('tim', 'EC0D6302E35B7E792DF9DA4A5FE0DB3B90FCAB65A6215215771BF96D498A01DA8234769E1CE8269A105E9112F374FDAB2158E7DA58CDC1348A732351C38E12A0', 'C59EB438D1E24CACA2B1A48BC129348589D49303858E493FBE906A9158B7D5DC');");
    SQL.add("insert into user_roles values ('tim', 'dev');");
    SQL.add("insert into user_roles values ('tim', 'admin');");
    SQL.add("insert into roles_perms values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms values ('admin', 'merge_pr');");

    // add another user using nonces
    SQL.add("insert into user values ('paulo', '4EFC18C18180F20905B79EA06D24F866382E9888957195E3C36EFA603C5194AD4E56685579FC4A9C5144EE093B00E1E208C344E80703DEEE28D4FCF3C7778F24$0', 'E1BDFAF66074169738F593626ABDE48E013CA17D87CDFF07F18FC5D7FBBFA427');");

    // and a second set of tables with slight differences

    SQL.add("drop table if exists user2;");
    SQL.add("drop table if exists user_roles2;");
    SQL.add("drop table if exists roles_perms2;");
    SQL.add("create table user2 (user_name varchar(255), pwd varchar(255), pwd_salt varchar(255) );");
    SQL.add("create table user_roles2 (user_name varchar(255), role varchar(255));");
    SQL.add("create table roles_perms2 (role varchar(255), perm varchar(255));");

    SQL.add("insert into user2 values ('tim', 'EC0D6302E35B7E792DF9DA4A5FE0DB3B90FCAB65A6215215771BF96D498A01DA8234769E1CE8269A105E9112F374FDAB2158E7DA58CDC1348A732351C38E12A0', 'C59EB438D1E24CACA2B1A48BC129348589D49303858E493FBE906A9158B7D5DC');");
    SQL.add("insert into user_roles2 values ('tim', 'dev');");
    SQL.add("insert into user_roles2 values ('tim', 'admin');");
    SQL.add("insert into roles_perms2 values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms2 values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms2 values ('admin', 'merge_pr');");

    // add another user using nonces
    SQL.add("insert into user2 values ('paulo', '4EFC18C18180F20905B79EA06D24F866382E9888957195E3C36EFA603C5194AD4E56685579FC4A9C5144EE093B00E1E208C344E80703DEEE28D4FCF3C7778F24$0', 'E1BDFAF66074169738F593626ABDE48E013CA17D87CDFF07F18FC5D7FBBFA427');");
  }

  @BeforeClass
  public static void createDb() throws Exception {
    Connection conn = DriverManager.getConnection(config().getString("url"));
    for (String sql : SQL) {
      System.out.println("Executing: " + sql);
      conn.createStatement().execute(sql);
    }
  }

  protected static JsonObject config() {
    return new JsonObject()
      .put("url", "jdbc:hsqldb:mem:test?shutdown=true")
      .put("driver_class", "org.hsqldb.jdbcDriver");
  }

  protected JDBCAuth authProvider;

  @Before
  public void setUp() throws Exception {
    authProvider = createProvider().setNonces(new JsonArray().add("queiM3ayei1ahCheicupohphioveer0O"));
  }

  protected JDBCAuth createProvider() {
    JDBCClient client = JDBCClient.create(rule.vertx(), config());
    return JDBCAuth.create(rule.vertx(), client);
  }

  @Test
  public void testAuthenticate(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testAuthenticateFailBadPwd(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "eggs");
    authProvider
      .authenticate(credentials)
      .onSuccess(user -> should.fail("This test should have failed!"))
      .onFailure(err -> {
        should.assertEquals("Invalid username/password", err.getMessage());
        test.complete();
      });
  }

  @Test
  public void testAuthenticateFailBadUser(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("blah", "whatever");
    authProvider
      .authenticate(credentials)
      .onSuccess(user -> should.fail("This test should have failed!"))
      .onFailure(err -> {
        should.assertEquals("Invalid username/password", err.getMessage());
        test.complete();
      });
  }

  @Test
  public void testAuthoriseHasRole(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        user.isAuthorized("role:dev")
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertTrue(has);
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasRole(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        user.isAuthorized("role:manager")
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertFalse(has);
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseHasPermission(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        user.isAuthorized("commit_code")
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertTrue(has);
            test.complete();
          });
      });
  }

  @Test
  public void testAuthoriseNotHasPermission(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("tim", "sausages");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        user.isAuthorized("eat_sandwich")
          .onFailure(should::fail)
          .onSuccess(has -> {
            should.assertFalse(has);
            test.complete();
          });
      });
  }

  @Test
  public void testAuthenticateWithNonce(TestContext should) {
    final Async test = should.async();

    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("paulo", "secret");
    authProvider
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }
}
