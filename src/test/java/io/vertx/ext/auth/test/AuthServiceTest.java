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

package io.vertx.ext.auth.test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.PropertiesAuthRealmConstants;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceTest extends VertxTestBase {

  protected volatile AuthService authService;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authService = AuthService.create(vertx, getConfig());
    authService.start();
  }

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    config.put(PropertiesAuthRealmConstants.PROPERTIES_PROPS_PATH_FIELD, "classpath:test-auth.properties");
    return config;
  }

  @Override
  protected void tearDown() throws Exception {
    authService.stop();
    super.tearDown();
  }

  @Test
  public void testSimpleLogin() {
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleLoginFail() {
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "wrongpassword");
    authService.login(credentials, onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRole() {
    authService.hasRole("tim", "administrator", onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasRole() {
    authService.hasRole("tim", "manager", onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRoles() {
    Set<String> roles = new HashSet<>(Arrays.asList("administrator", "developer"));
    authService.hasRoles("tim", roles, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasRoles() {
    Set<String> roles = new HashSet<>(Arrays.asList("administrator", "developer"));
    authService.hasRoles("bob", roles, onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasPermission() {
    authService.hasPermission("tim", "do_actual_work", onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermission() {
    authService.hasPermission("bob", "play_golf", onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasPermissions() {
    Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "play_golf"));
    authService.hasPermissions("tim", permissions, onSuccess(res -> {
      assertTrue(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermissions() {
    Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "play_golf"));
    authService.hasPermissions("bob", permissions, onSuccess(res -> {
      assertFalse(res);
      testComplete();
    }));
    await();
  }

}
