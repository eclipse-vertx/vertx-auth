/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.properties;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.properties.PropertyFileAuthentication;
import io.vertx.test.core.VertxTestBase;

import org.junit.Test;

import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class PropertyFileAuthenticationTest extends VertxTestBase {

  private AuthProvider authProvider;
  
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
      this.<Boolean>executeTwice(handler -> user.isAuthorized("role:morris_dancer", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      }));
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("role:manager", handler), res -> {
      assertTrue(res.succeeded());
      assertFalse(res.result());
    }));
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("do_actual_work", handler), res -> {
      assertTrue(res.succeeded());
      assertTrue(res.result());
    }));
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    loginThen(user -> this.<Boolean>executeTwice(handler -> user.isAuthorized("play_golf", handler), res -> {
      assertTrue(res.succeeded());
      assertFalse(res.result());
    }));
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

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = PropertyFileAuthentication.create(vertx, this.getClass().getResource("/test-auth.properties").getFile());
  }

  @Test
  public void testHasWildcardPermission() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "paulo").put("password", "secret");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      // paulo can do anything...
      user.isAuthorized("do_actual_work", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testHasWildcardMatchPermission() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "editor").put("password", "secret");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      // editor can edit any newsletter item...
      user.isAuthorized("newsletter:edit:13", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

}
