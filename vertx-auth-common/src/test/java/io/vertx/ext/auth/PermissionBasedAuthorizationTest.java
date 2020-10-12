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
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.authorization.impl.PermissionBasedAuthorizationConverter;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class PermissionBasedAuthorizationTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1"), PermissionBasedAuthorizationConverter::encode,
        PermissionBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1").setResource("resource"),
        PermissionBasedAuthorizationConverter::encode, PermissionBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    assertTrue(PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies2() {
    assertTrue(PermissionBasedAuthorization.create("p1").setResource("r1")
      .verify(PermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies3() {
    assertFalse(PermissionBasedAuthorization.create("p1").setResource("r1").verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies4() {
    assertFalse(PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies5() {
    assertFalse(PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p2")));
  }

  @Test
  public void testVerifyWildcard() {
    assertTrue(PermissionBasedAuthorization.create("p1").verify(WildcardPermissionBasedAuthorization.create("p1")));
    assertTrue(PermissionBasedAuthorization.create("p1.*").verify(WildcardPermissionBasedAuthorization.create("p1.*")));
  }

  @Test
  public void testMatch1(TestContext should) {
    final Async test = should.async();

    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.fromName("dummy user");
      user.authorizations().add("providerId", PermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertEquals(true, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost", should.asyncAssertSuccess(s -> {
      rule.vertx().createHttpClient().request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r1", should.asyncAssertSuccess(req -> {
        req.send(should.asyncAssertSuccess(res -> {
          server.close(close -> test.complete());
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
      user.authorizations().add("providerId", PermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertEquals(false, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost", should.asyncAssertSuccess(s -> {
      rule.vertx().createHttpClient().request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r2", should.asyncAssertSuccess(req -> {
        req.send(should.asyncAssertSuccess(res -> {
          server.close(close -> test.complete());
        }));
      }));
    }));
  }
}
