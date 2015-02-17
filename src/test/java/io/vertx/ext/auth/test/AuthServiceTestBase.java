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
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public abstract class AuthServiceTestBase extends VertxTestBase {

  protected AuthService authService;

  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

  @Override
  protected void tearDown() throws Exception {
    authService.stop();
    super.tearDown();
  }

  protected abstract void initAuthService(long reaperPeriod) throws Exception;

  protected abstract void initAuthService() throws Exception;

  @Test
  public void testSimpleLogin() throws Exception {
    initAuthService();
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleLoginFail() throws Exception {
    initAuthService();
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "wrongpassword");
    authService.login(credentials, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRole() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      authService.hasRole(sessID, "morris_dancer", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasRoleNotLoggedIn() throws Exception {
    initAuthService();
    authService.hasRole("uqhwdihuqwd", "morris_dancer", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      authService.hasRole(sessID, "manager", onSuccess(res -> {
        assertFalse(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasRoles() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
      authService.hasRoles(sessID, roles, onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasRolesNotLoggedIn() throws Exception {
    initAuthService();
    Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
    authService.hasRoles("uhqwdihu", roles, onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasRoles() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> roles = new HashSet<>(Arrays.asList("administrator", "developer"));
      authService.hasRoles(sessID, roles, onSuccess(res -> {
        assertFalse(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      authService.hasPermission(sessID, "do_actual_work", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasPermissionNotLoggedIn() throws Exception {
    initAuthService();
    authService.hasPermission("uqhwdihuqwd", "morris_dancer", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      authService.hasPermission(sessID, "play_golf", onSuccess(res -> {
        assertFalse(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasPermissions() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
      authService.hasPermissions(sessID, permissions, onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testHasPermissionsNotLoggedIn() throws Exception {
    initAuthService();
    Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
    authService.hasPermissions("uhqwdihu", permissions, onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermissions() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "eat_cheese"));
      authService.hasPermissions(sessID, permissions, onSuccess(res -> {
        assertFalse(res);
        testComplete();
      }));
    });
    await();
  }

  @Test
  public void testLoginTimeout() throws Exception {
    initAuthService(100);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 100, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      vertx.setTimer(1000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onFailure(thr -> {
          assertNotNull(thr);
          assertEquals("not logged in", thr.getMessage());
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testTouchSession() throws Exception {
    initAuthService(500);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 100, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.refreshLoginSession(sessionID, res -> {
        assertTrue(res.succeeded());
      }));
      vertx.setTimer(2000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(res -> {
          assertTrue(res);
          vertx.cancelTimer(pid);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testTouchSessionNotLoggedIn() throws Exception {
    initAuthService();
    authService.refreshLoginSession("qijsoiqsj", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testLogout() throws Exception {
    initAuthService();
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      authService.logout(sessionID, onSuccess(v -> {
        authService.hasRole(sessionID, "morris_dancer", onFailure(thr -> {
          assertNotNull(thr);
          assertEquals("not logged in", thr.getMessage());
          testComplete();
        }));
      }));
    }));
    await();
  }

  @Test
  public void testLogoutNotLoggedIn() throws Exception {
    initAuthService();
    authService.logout("qijsoiqsj", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  private void loginThen(Consumer<String> runner) throws Exception {
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      runner.accept(sessionID);
    }));
  }
}
