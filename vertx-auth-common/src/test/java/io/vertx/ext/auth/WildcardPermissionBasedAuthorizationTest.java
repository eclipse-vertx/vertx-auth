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
package io.vertx.ext.auth;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.authorization.impl.WildcardPermissionBasedAuthorizationConverter;
import io.vertx.ext.auth.user.User;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(VertxUnitRunner.class)
public class WildcardPermissionBasedAuthorizationTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1"),
      WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1").setResource("resource"),
      WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    assertTrue(WildcardPermissionBasedAuthorization.create("wp1").verify(WildcardPermissionBasedAuthorization.create("wp1")));
  }

  @Test
  public void testImplies2() {
    assertTrue(WildcardPermissionBasedAuthorization.create("*").verify(WildcardPermissionBasedAuthorization.create("wp1")));
  }

  @Test
  public void testImplies3() {
    assertTrue(WildcardPermissionBasedAuthorization.create("printer:*")
      .verify(WildcardPermissionBasedAuthorization.create("printer:read")));
  }

  @Test
  public void testImplies4() {
    assertTrue(WildcardPermissionBasedAuthorization.create("*:read")
      .verify(WildcardPermissionBasedAuthorization.create("printer:read")));
  }

  @Test
  public void testImplies5() {
    assertTrue(WildcardPermissionBasedAuthorization.create("p1")
      .verify(WildcardPermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies6() {
    assertFalse(WildcardPermissionBasedAuthorization.create("p1").setResource("r1")
      .verify(WildcardPermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies7() {
    assertFalse(WildcardPermissionBasedAuthorization.create("wp1").verify(WildcardPermissionBasedAuthorization.create("wp2")));
  }

  @Test
  public void testImplies8() {
    assertFalse(WildcardPermissionBasedAuthorization.create("printer:read")
      .verify(WildcardPermissionBasedAuthorization.create("*")));
  }

  @Test
  public void testImplies9() {
    assertFalse(WildcardPermissionBasedAuthorization.create("*:read")
      .verify(WildcardPermissionBasedAuthorization.create("printer:edit")));
  }

  @Test
  public void testVerifyPermisionAuthorization() {
    assertTrue(WildcardPermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p1")));
    assertTrue(WildcardPermissionBasedAuthorization.create("p1.*").verify(PermissionBasedAuthorization.create("p1.*")));
    assertTrue(WildcardPermissionBasedAuthorization.create("*").verify(PermissionBasedAuthorization.create("*")));
    assertTrue(WildcardPermissionBasedAuthorization.create("*").verify(PermissionBasedAuthorization.create("test")));
  }

  @Test
  public void testMatch1(TestContext should) {
    final Async test = should.async();
    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.fromName("dummy user");
      user.authorizations().put("providerId", WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertTrue(WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost").onComplete(should.asyncAssertSuccess(s -> {
      rule.vertx().createHttpClient().request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r1").onComplete(should.asyncAssertSuccess(req -> {
        req.send().onComplete(should.asyncAssertSuccess(res -> {
          server.close().onComplete(close -> test.complete());
        }));
      }));
    }));
  }

  @Test
  public void testMatch2(TestContext should) {
    final Async test = should.async();
    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.fromName("dummy user");
      user.authorizations().put("providerId", WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertFalse(WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost").onComplete(should.asyncAssertSuccess(s -> {
      rule.vertx().createHttpClient().request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r2").onComplete(should.asyncAssertSuccess(req -> {
        req.send().onComplete(should.asyncAssertSuccess(res -> {
          server.close().onComplete(close -> test.complete());
        }));
      }));
    }));
  }
}
