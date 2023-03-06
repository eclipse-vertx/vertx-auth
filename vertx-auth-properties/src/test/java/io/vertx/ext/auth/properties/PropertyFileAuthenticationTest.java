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

import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.function.Consumer;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@RunWith(VertxUnitRunner.class)
public class PropertyFileAuthenticationTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private AuthenticationProvider authn;
  private AuthorizationProvider authz;

  @Test
  public void testSimpleAuthenticate(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("tim", "sausages");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void testSimpleAuthenticateFailWrongPassword(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("tim", "wrongpassword");
    authn.authenticate(authInfo)
      .onSuccess(user -> should.fail("Not Expected"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testSimpleAuthenticateFailWrongUser(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("frank", "sausages");
    authn.authenticate(authInfo)
      .onSuccess(user -> should.fail("Not Expected"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testHasRole(TestContext should) {
    final Async test = should.async();
    loginThen(should, user ->
      authz.getAuthorizations(user)
        .onFailure(should::fail)
        .onSuccess(v -> {
          should.assertTrue(
            RoleBasedAuthorization.create("morris_dancer").match(AuthorizationContext.create(user)));

          should.assertTrue(
            RoleBasedAuthorization.create("morris_dancer").match(AuthorizationContext.create(user)));

          test.complete();
        }));
  }

  @Test
  public void testNotHasRole(TestContext should) {
    final Async test = should.async();
    loginThen(should, user ->
      authz.getAuthorizations(user)
        .onFailure(should::fail)
        .onSuccess(v -> {
          should.assertFalse(
            RoleBasedAuthorization.create("manager").match(AuthorizationContext.create(user)));

          should.assertFalse(
            RoleBasedAuthorization.create("manager").match(AuthorizationContext.create(user)));

          test.complete();
        }));
  }

  @Test
  public void testHasPermission(TestContext should) {
    final Async test = should.async();
    loginThen(should, user ->
      authz.getAuthorizations(user)
        .onFailure(should::fail)
        .onSuccess(v -> {
          should.assertTrue(
            PermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));

          should.assertTrue(
            PermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));

          test.complete();
        }));
  }

  @Test
  public void testNotHasPermission(TestContext should) {
    final Async test = should.async();
    loginThen(should, user ->
      authz.getAuthorizations(user)
        .onFailure(should::fail)
        .onSuccess(v -> {
          should.assertFalse(
            PermissionBasedAuthorization.create("play_golf").match(AuthorizationContext.create(user)));

          should.assertFalse(
            PermissionBasedAuthorization.create("play_golf").match(AuthorizationContext.create(user)));

          test.complete();
        }));
  }

  private void loginThen(TestContext should, Consumer<User> runner) {
    Credentials authInfo = new UsernamePasswordCredentials("tim", "sausages");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        runner.accept(user);
      });
  }

  @Before
  public void setUp() throws Exception {
    authn = PropertyFileAuthentication.create(rule.vertx(), this.getClass().getResource("/test-auth.properties").getFile());
    authz = PropertyFileAuthorization.create(rule.vertx(), this.getClass().getResource("/test-auth.properties").getFile());
  }

  @Test
  public void testHasWildcardPermission(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("paulo", "secret");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);

        authz.getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(v -> {
            // paulo can do anything...
            should.assertTrue(
              WildcardPermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));
            test.complete();
          });
      });
  }

  @Test
  public void testHasWildcardMatchPermission(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("editor", "secret");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        // editor can edit any newsletter item...
        authz.getAuthorizations(user)
          .onFailure(should::fail)
          .onSuccess(u -> {
            should.assertTrue(
              WildcardPermissionBasedAuthorization.create("newsletter:edit:13").match(AuthorizationContext.create(user)));
            test.complete();
          });
      });
  }
}
