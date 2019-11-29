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

import org.junit.BeforeClass;
import org.junit.Test;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
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

    SQL.add("insert into user_roles values ('tim', 'dev');");
    SQL.add("insert into user_roles values ('tim', 'admin');");
    SQL.add("insert into roles_perms values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms values ('admin', 'merge_pr');");

    // and a second set of tables with slight differences
    SQL.add("drop table if exists user_roles2;");
    SQL.add("drop table if exists roles_perms2;");
    SQL.add("create table user_roles2 (user_name varchar(255), role varchar(255));");
    SQL.add("create table roles_perms2 (role varchar(255), perm varchar(255));");

    SQL.add("insert into user_roles2 values ('tim', 'dev');");
    SQL.add("insert into user_roles2 values ('tim', 'admin');");
    SQL.add("insert into roles_perms2 values ('dev', 'commit_code');");
    SQL.add("insert into roles_perms2 values ('dev', 'eat_pizza');");
    SQL.add("insert into roles_perms2 values ('admin', 'merge_pr');");
  }

  private JDBCAuthorization authorizationProvider;
  private JDBCAuthorizationOptions authorizationOptions;

  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

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

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  private void fillUserAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizationProvider().getAuthorizations(user, authorizationResponse -> {
      if (authorizationResponse.succeeded()) {
        user.authorizations().add(getAuthorizationProvider().getId(), authorizationResponse.result());
      }
      handler.handle(Future.succeededFuture());
    });
  }

  @Test
  public void testAuthoriseHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, done -> {
        user.isAuthorized("role:dev", onSuccess(has -> {
          assertTrue(has);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, done -> {
        user.isAuthorized("role:manager", onSuccess(has -> {
          assertFalse(has);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testAuthoriseHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, done -> {
        user.isAuthorized("commit_code", onSuccess(has -> {
          assertTrue(has);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put("username", "tim").put("password", "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, done -> {
        user.isAuthorized("eat_sandwich", onSuccess(has -> {
          assertFalse(has);
          testComplete();
        }));
      });
    }));
    await();
  }

}
