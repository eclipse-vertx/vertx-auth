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

import io.vertx.core.http.HttpServer;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.impl.WildcardPermissionBasedAuthorizationConverter;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class WildcardPermissionBasedAuthorizationTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

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
  }

  @Test
  public void testMatch1(TestContext should) {
    final Async test = should.async();
    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add("providerId", WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertTrue(WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost", listen -> {
      if (listen.failed()) {
        should.fail(listen.cause());
        return;
      }
      rule.vertx().createHttpClient().getNow(listen.result().actualPort(), "localhost", "/?variable1=r1", res -> {
        if (res.failed()) {
          should.fail(res.cause());
          return;
        }
        server.close(close -> test.complete());
      });
    });
  }

  @Test
  public void testMatch2(TestContext should) {
    final Async test = should.async();
    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add("providerId", WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertFalse(WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost", listen -> {
      if (listen.failed()) {
        should.fail(listen.cause());
        return;
      }

      rule.vertx().createHttpClient().getNow(listen.result().actualPort(), "localhost", "/?variable1=r2", res -> {
        if (res.failed()) {
          should.fail(res.cause());
          return;
        }
        server.close(close -> test.complete());
      });
    });
  }
}
