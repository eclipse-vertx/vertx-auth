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

import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.authorization.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.authorization.impl.RoleBasedAuthorizationConverter;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(VertxUnitRunner.class)
public class RoleBasedAuthorizationTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1"), RoleBasedAuthorizationConverter::encode,
      RoleBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1").setResource("resource"),
      RoleBasedAuthorizationConverter::encode, RoleBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    assertTrue(RoleBasedAuthorization.create("role1").verify(RoleBasedAuthorization.create("role1")));
  }

  @Test
  public void testImplies2() {
    assertTrue(RoleBasedAuthorization.create("p1").setResource("r1")
      .verify(RoleBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies3() {
    assertFalse(RoleBasedAuthorization.create("p1").setResource("r1").verify(RoleBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies4() {
    assertFalse(RoleBasedAuthorization.create("p1").verify(RoleBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies5() {
    assertFalse(RoleBasedAuthorization.create("role1").verify(RoleBasedAuthorization.create("role2")));
  }

  @Test
  public void testMatch1(TestContext should) {
    Async test = should.async();
    HttpClient client = rule.vertx().createHttpClient();

    final HttpServer server = rule.vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.fromName("dummy user");
      user.authorizations().put("providerId", Collections.singleton(RoleBasedAuthorization.create("p1").setResource("r1")));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertTrue(RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost").onComplete(should.asyncAssertSuccess(s -> {
      client.request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r1").onComplete(should.asyncAssertSuccess(req -> {
        req.send().onComplete(should.asyncAssertSuccess(res -> {
          server.close().onComplete(close -> test.complete());
        }));
      }));
    }));
  }

  @Test
  public void testMatch2(TestContext should) {
    Async test = should.async();

    HttpServer server = rule.vertx().createHttpServer();
    HttpClient client = rule.vertx().createHttpClient();
    server.requestHandler(request -> {
      User user = User.fromName("dummy user");
      user.authorizations().put("providerId", Collections.singleton(RoleBasedAuthorization.create("p1").setResource("r1")));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      should.assertFalse(RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(0, "localhost").onComplete(should.asyncAssertSuccess(s -> {
      client.request(HttpMethod.GET, s.actualPort(), "localhost", "/?variable1=r2").onComplete(should.asyncAssertSuccess(req -> {
        req.send().onComplete(should.asyncAssertSuccess(res -> {
          server.close().onComplete(close -> test.complete());
        }));
      }));
    }));
  }

}
