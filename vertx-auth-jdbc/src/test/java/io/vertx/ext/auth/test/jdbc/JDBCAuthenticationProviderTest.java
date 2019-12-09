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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jdbc.JDBCAuthentication;
import io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions;
import io.vertx.ext.auth.jdbc.JDBCHashStrategy;
import io.vertx.ext.jdbc.JDBCClient;
import io.vertx.test.core.VertxTestBase;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class JDBCAuthenticationProviderTest extends VertxTestBase {

  static final List<String> SQL = new ArrayList<>();

  static {
    SQL.add("drop table if exists user;");
    SQL.add("create table user (username varchar(255), password varchar(255), password_salt varchar(255) );");
//    SQL.add("create table user_roles (username varchar(255), role varchar(255));");
//    SQL.add("create table roles_perms (role varchar(255), perm varchar(255));");

    SQL.add(
      "insert into user values ('tim', 'EC0D6302E35B7E792DF9DA4A5FE0DB3B90FCAB65A6215215771BF96D498A01DA8234769E1CE8269A105E9112F374FDAB2158E7DA58CDC1348A732351C38E12A0', 'C59EB438D1E24CACA2B1A48BC129348589D49303858E493FBE906A9158B7D5DC');");
//    SQL.add("insert into user_roles values ('tim', 'dev');");
//    SQL.add("insert into user_roles values ('tim', 'admin');");
//    SQL.add("insert into roles_perms values ('dev', 'commit_code');");
//    SQL.add("insert into roles_perms values ('dev', 'eat_pizza');");
//    SQL.add("insert into roles_perms values ('admin', 'merge_pr');");

    // add another user using nonces
    SQL.add(
      "insert into user values ('paulo', '4EFC18C18180F20905B79EA06D24F866382E9888957195E3C36EFA603C5194AD4E56685579FC4A9C5144EE093B00E1E208C344E80703DEEE28D4FCF3C7778F24$0', 'E1BDFAF66074169738F593626ABDE48E013CA17D87CDFF07F18FC5D7FBBFA427');");

    // add a modern user
    SQL.add(
      "insert into user values ('lopus', '$pbkdf2$1drH02tXcgS5ipJIf8v/AlL/qm3CjAgAp7Qt3hyJx/c=$/lONU4cTa3ayMRJbHIup47nX/1HhysyzDA0dpoFpsf727LoGH2OZ+SyFCGtv/pIEZK3mQtJv+yjzD+W0quF6xg==', null);");

    // and a second set of tables with slight differences

    SQL.add("drop table if exists user2;");
//    SQL.add("drop table if exists user_roles2;");
//    SQL.add("drop table if exists roles_perms2;");
    SQL.add("create table user2 (user_name varchar(255), pwd varchar(255), pwd_salt varchar(255) );");
//    SQL.add("create table user_roles2 (user_name varchar(255), role varchar(255));");
//    SQL.add("create table roles_perms2 (role varchar(255), perm varchar(255));");

    SQL.add(
      "insert into user2 values ('tim', 'EC0D6302E35B7E792DF9DA4A5FE0DB3B90FCAB65A6215215771BF96D498A01DA8234769E1CE8269A105E9112F374FDAB2158E7DA58CDC1348A732351C38E12A0', 'C59EB438D1E24CACA2B1A48BC129348589D49303858E493FBE906A9158B7D5DC');");
//    SQL.add("insert into user_roles2 values ('tim', 'dev');");
//    SQL.add("insert into user_roles2 values ('tim', 'admin');");
//    SQL.add("insert into roles_perms2 values ('dev', 'commit_code');");
//    SQL.add("insert into roles_perms2 values ('dev', 'eat_pizza');");
//    SQL.add("insert into roles_perms2 values ('admin', 'merge_pr');");

    // add another user using nonces
    SQL.add(
      "insert into user2 values ('paulo', '4EFC18C18180F20905B79EA06D24F866382E9888957195E3C36EFA603C5194AD4E56685579FC4A9C5144EE093B00E1E208C344E80703DEEE28D4FCF3C7778F24$0', 'E1BDFAF66074169738F593626ABDE48E013CA17D87CDFF07F18FC5D7FBBFA427');");
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
    return new JsonObject().put("url", "jdbc:hsqldb:mem:test?shutdown=true").put("driver_class",
      "org.hsqldb.jdbcDriver");
  }

  private JDBCHashStrategy jdbcHashStrategy;
  private JDBCAuthentication authenticationProvider;
  private JDBCAuthentication phcAuthenticationProvider;
  private JDBCAuthenticationOptions authenticationOptions;
  private JDBCClient jdbcClient;

  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

  protected JDBCClient getJDBCCLient() {
    if (jdbcClient == null) {
      jdbcClient = JDBCClient.createNonShared(vertx, config());
    }
    return jdbcClient;
  }

  protected JDBCHashStrategy getHashStrategy() {
    if (jdbcHashStrategy == null) {
      jdbcHashStrategy = JDBCHashStrategy.createSHA512(vertx);
      jdbcHashStrategy.setNonces(new JsonArray().add("queiM3ayei1ahCheicupohphioveer0O"));
    }
    return jdbcHashStrategy;
  }

  protected JDBCAuthentication getAuthenticationProvider() {
    if (authenticationProvider == null) {
      authenticationProvider = JDBCAuthentication.create(getJDBCCLient(), getHashStrategy(), new JDBCAuthenticationOptions());
    }
    return authenticationProvider;
  }

  protected JDBCAuthentication getPHCAuthenticationProvider() {
    if (phcAuthenticationProvider == null) {
      phcAuthenticationProvider = JDBCAuthentication.create(getJDBCCLient(), new JDBCAuthenticationOptions());
    }
    return phcAuthenticationProvider;
  }

  protected JDBCAuthenticationOptions getAuthenticationOptions() {
    if (authenticationOptions == null) {
      authenticationOptions = new JDBCAuthenticationOptions();
    }
    return authenticationOptions;
  }

  @Override
  protected void tearDown() throws Exception {
    getJDBCCLient().close();
    super.tearDown();
  }

  @Test
  public void testAuthenticate() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadPwd() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "eggs");
    getAuthenticationProvider().authenticate(authInfo, onFailure(v -> {
      assertEquals("Invalid username/password", v.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadUser() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "blah").put("password", "whatever");
    getAuthenticationProvider().authenticate(authInfo, onFailure(v -> {
      assertEquals("Invalid username/password", v.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateWithNonce() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "paulo").put("password", "secret");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testPHC() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "lopus").put("password", "secret");

    getPHCAuthenticationProvider()
      .authenticate(authInfo, onSuccess(user -> {
        assertNotNull(user);
        testComplete();
      }));
    await();
  }
}
