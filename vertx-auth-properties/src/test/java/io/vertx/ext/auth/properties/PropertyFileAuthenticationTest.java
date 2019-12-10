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

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authorization.*;
import io.vertx.test.core.VertxTestBase;

import org.junit.Test;

import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class PropertyFileAuthenticationTest extends VertxTestBase {

  private AuthenticationProvider authn;
  private AuthorizationProvider authz;

  @Test
  public void testSimpleAuthenticate() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authn.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongPassword() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "wrongpassword");
    authn.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testSimpleAuthenticateFailWrongUser() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "frank").put("password", "sausages");
    authn.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testHasRole() throws Exception {
    loginThen(user ->
      authz.getAuthorizations(user, get -> {
        assertTrue(get.succeeded());
        assertTrue(
          RoleBasedAuthorization.create("morris_dancer").match(AuthorizationContext.create(user)));

        assertTrue(
          RoleBasedAuthorization.create("morris_dancer").match(AuthorizationContext.create(user)));

        testComplete();
      }));
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    loginThen(user -> authz.getAuthorizations(user, get -> {
      assertTrue(get.succeeded());
      assertFalse(
        RoleBasedAuthorization.create("manager").match(AuthorizationContext.create(user)));

      assertFalse(
        RoleBasedAuthorization.create("manager").match(AuthorizationContext.create(user)));

      testComplete();
    }));
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    loginThen(user -> authz.getAuthorizations(user, get -> {
      assertTrue(get.succeeded());
      assertTrue(
        PermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));

      assertTrue(
        PermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));

      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    loginThen(user -> authz.getAuthorizations(user, get -> {
      assertTrue(get.succeeded());
      assertFalse(
        PermissionBasedAuthorization.create("play_golf").match(AuthorizationContext.create(user)));

      assertFalse(
        PermissionBasedAuthorization.create("play_golf").match(AuthorizationContext.create(user)));

      testComplete();
    }));
    await();
  }

  private void loginThen(Consumer<User> runner) {
    JsonObject authInfo = new JsonObject().put("username", "tim").put("password", "sausages");
    authn.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      runner.accept(user);
    }));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authn = PropertyFileAuthentication.create(vertx, this.getClass().getResource("/test-auth.properties").getFile());
    authz = PropertyFileAuthorization.create(vertx, this.getClass().getResource("/test-auth.properties").getFile());
  }

  @Test
  public void testHasWildcardPermission() {
    JsonObject authInfo = new JsonObject().put("username", "paulo").put("password", "secret");
    authn.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      authz.getAuthorizations(user, get -> {
        assertTrue(get.succeeded());
        // paulo can do anything...
        assertTrue(
          WildcardPermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));
        testComplete();
      });
    }));
    await();
  }

  @Test
  public void testHasWildcardMatchPermission() throws Exception {
    JsonObject authInfo = new JsonObject().put("username", "editor").put("password", "secret");
    authn.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      // editor can edit any newsletter item...
      authz.getAuthorizations(user, get -> {
        assertTrue(get.succeeded());
        assertTrue(
          WildcardPermissionBasedAuthorization.create("newsletter:edit:13").match(AuthorizationContext.create(user)));
        testComplete();
      });
    }));
    await();
  }

}
