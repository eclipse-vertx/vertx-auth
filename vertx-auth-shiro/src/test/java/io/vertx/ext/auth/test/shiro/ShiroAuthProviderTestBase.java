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

package io.vertx.ext.auth.test.shiro;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public abstract class ShiroAuthProviderTestBase extends VertxTestBase {

  protected AuthProvider authProvider;

  @Test
  public void testSimpleAuthenticate() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongPassword() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "wrongpassword");
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongUser() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "frank").put("password", "sausages");
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRole() throws Exception {
    loginThen(user ->
      this.<Boolean>executeTwice(handler -> user.hasRole("morris_dancer", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      }));
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    loginThen(user -> {
      this.<Boolean>executeTwice(handler -> user.hasRole("manager", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasRoles() throws Exception {
    loginThen(user -> {
      Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
      this.<Boolean>executeTwice(handler -> user.hasRoles(roles, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testNotHasRoles() throws Exception {
    loginThen(user -> {
      Set<String> roles = new HashSet<>(Arrays.asList("administrator", "developer"));
      this.<Boolean>executeTwice(handler -> user.hasRoles(roles, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    loginThen(user -> {
      this.<Boolean>executeTwice(handler -> user.hasPermission("do_actual_work", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    loginThen(user -> {
      this.<Boolean>executeTwice(handler -> user.hasPermission("play_golf", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissions() throws Exception {
    loginThen(user -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
      this.<Boolean>executeTwice(handler -> user.hasPermissions(permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testNotHasPermissions() throws Exception {
    loginThen(user -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "eat_cheese"));
      this.<Boolean>executeTwice(handler -> user.hasPermissions(permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  private void loginThen(Consumer<User> runner) throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      runner.accept(user);
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
