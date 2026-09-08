/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.tests;

import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.properties.PropertyFileAuthentication;
import io.vertx.ext.auth.properties.PropertyFileAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class PropertyFileBufferAuthenticationTest {

  private static final Buffer CONTENT = Buffer.buffer(
    "user.tim=sausages,morris_dancer,developer\n" +
      "role.morris_dancer=bang_sticks\n" +
      "role.developer=do_actual_work\n");

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private AuthenticationProvider authn;
  private AuthorizationProvider authz;

  @Before
  public void setUp() throws Exception {
    authn = PropertyFileAuthentication.create(rule.vertx(), CONTENT);
    authz = PropertyFileAuthorization.create(rule.vertx(), CONTENT);
  }

  @Test
  public void testSimpleAuthenticate(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("tim", "sausages");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        should.assertEquals("tim", user.principal().getString("username"));
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
  public void testHasRoleAndPermission(TestContext should) {
    final Async test = should.async();
    Credentials authInfo = new UsernamePasswordCredentials("tim", "sausages");
    authn.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> authz.getAuthorizations(user)
        .onFailure(should::fail)
        .onSuccess(v -> {
          should.assertTrue(
            RoleBasedAuthorization.create("morris_dancer").match(AuthorizationContext.create(user)));
          should.assertTrue(
            PermissionBasedAuthorization.create("do_actual_work").match(AuthorizationContext.create(user)));
          test.complete();
        }));
  }
}
