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

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
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
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.login(principal, credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleLoginFail() throws Exception {
    initAuthService();
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "wrongpassword");
    authService.login(principal, credentials, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRole() throws Exception {
    initAuthService();
    loginThen(sessID ->
      this.<Boolean>executeTwice(handler -> authService.hasRole(sessID, "morris_dancer", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      }));
    await();
  }

  @Test
  public void testHasRoleNotLoggedIn() throws Exception {
    initAuthService();
    this.<Boolean>executeTwice(handler -> authService.hasRole("uqhwdihuqwd", "morris_dancer", handler), res -> {
      assertFalse(res.succeeded());
      assertEquals("not logged in", res.cause().getMessage());
    });
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean>executeTwice(handler -> authService.hasRole(sessID, "manager", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasRoles() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
      this.<Boolean>executeTwice(handler -> authService.hasRoles(sessID, roles, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
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
      this.<Boolean>executeTwice(handler -> authService.hasRoles(sessID, roles, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean>executeTwice(handler -> authService.hasPermission(sessID, "do_actual_work", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissionNotLoggedIn() throws Exception {
    initAuthService();
    this.<Boolean>executeTwice(handler -> authService.hasPermission("uqhwdihuqwd", "morris_dancer", handler), res -> {
      assertFalse(res.succeeded());
      assertEquals("not logged in", res.cause().getMessage());
    });
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean>executeTwice(handler -> authService.hasPermission(sessID, "play_golf", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissions() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
      this.<Boolean>executeTwice(handler -> authService.hasPermissions(sessID, permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
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
      this.<Boolean>executeTwice(handler -> authService.hasPermissions(sessID, permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testLoginTimeout() throws Exception {
    initAuthService(100);
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.loginWithTimeout(principal, credentials, 100, onSuccess(sessionID -> {
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
  public void testLoginNoTimeout() throws Exception {
    initAuthService(100);
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.loginWithTimeout(principal, credentials, 5000, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      vertx.setTimer(1000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(hasRole -> {
          assertTrue(hasRole);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testRefreshSession() throws Exception {
    initAuthService(500);
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.loginWithTimeout(principal, credentials, 200, onSuccess(sessionID -> {
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
  public void testRefreshSessionHasRole() throws Exception {
    initAuthService(500);
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.loginWithTimeout(principal, credentials, 200, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.hasRole(sessionID, "morris_dancer", res -> {
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
  public void testRefreshSessionHasPermission() throws Exception {
    initAuthService(500);
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.loginWithTimeout(principal, credentials, 200, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.hasPermission(sessionID, "bang_sticks", res -> {
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
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.login(principal, credentials, onSuccess(sessionID -> {
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
    JsonObject principal = new JsonObject().put("username", "tim");
    JsonObject credentials = new JsonObject().put("password", "sausages");
    authService.login(principal, credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      runner.accept(sessionID);
    }));
  }

  private <T> void executeTwice(Consumer<Handler<AsyncResult<T>>> action, Consumer<AsyncResult<T>> resultConsumer) {
    action.accept(res -> {
      resultConsumer.accept(res);
      action.accept(res2 -> {
        resultConsumer.accept(res);
        testComplete();
      });
    });
  }

}
