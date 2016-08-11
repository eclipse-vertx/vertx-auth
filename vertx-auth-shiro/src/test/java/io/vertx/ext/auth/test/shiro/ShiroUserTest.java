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

import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.shiro.impl.ShiroAuthProviderImpl;
import io.vertx.ext.auth.shiro.impl.ShiroUser;
import io.vertx.test.core.VertxTestBase;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.ExpiredSessionException;
import org.junit.Test;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroUserTest extends VertxTestBase {

  private void authenticate(Handler<User> onLoggedIn) {
    Realm realm = new TestShiroRealm();

    AuthProvider authProvider = new ShiroAuthProviderImpl(vertx, realm);
    JsonObject authInfo = new JsonObject()
        .put("username", "tim")
        .put("password", "sausages");

    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      onLoggedIn.handle(user);
    }));
  }

  @Test
  public void userDoesTimeout() {
    authenticate(user -> {
      ((ShiroUser) user).setSessionTimeout(0);

      vertx.setTimer(20, IGNORE -> {
        user.isAuthorised("foo", result -> {
          assertFalse(result.succeeded());
          assertTrue(result.cause() instanceof ExpiredSessionException);
          testComplete();
        });
      });
    });
    await();
  }

  @Test
  public void userDoesNotTimeout() {
    authenticate(user -> {

      vertx.setPeriodic(10, IGNORE -> {
        user.touch();

        // Set the timeout after the initial touch to reduce the possibility that a block in execution
        // could cause an incorrect timeout and fail the test
        ((ShiroUser) user).setSessionTimeout(200);
      });

      vertx.setTimer(300, IGNORE -> {
        user.isAuthorised("foo", result -> {
          assertTrue(result.succeeded());
          testComplete();
        });
      });
    });
    await();
  }
}
