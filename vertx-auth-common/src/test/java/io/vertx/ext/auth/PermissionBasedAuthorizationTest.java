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
import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.impl.PermissionBasedAuthorizationConverter;
import io.vertx.test.core.VertxTestBase;

public class PermissionBasedAuthorizationTest extends VertxTestBase {

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1"), PermissionBasedAuthorizationConverter::encode,
        PermissionBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(PermissionBasedAuthorization.create("p1").setResource("resource"),
        PermissionBasedAuthorizationConverter::encode, PermissionBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    Assert.assertEquals(true,
        PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies2() {
    Assert.assertEquals(true, PermissionBasedAuthorization.create("p1").setResource("r1")
        .verify(PermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies3() {
    Assert.assertEquals(false,
        PermissionBasedAuthorization.create("p1").setResource("r1").verify(PermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies4() {
    Assert.assertEquals(false,
        PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies5() {
    Assert.assertEquals(false,
        PermissionBasedAuthorization.create("p1").verify(PermissionBasedAuthorization.create("p2")));
  }

  @Test
  public void testMatch1() {
    final HttpServer server = vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add(PermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(true, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(9876, "localhost");
    vertx().createHttpClient().getNow(9876, "localhost", "/?variable1=r1", res -> {
      server.close();
      if (res.failed()) {
        fail(res.cause());
        return;
      }
      testComplete();
    });
    await();
  }

  @Test
  public void testMatch2() {
    final HttpServer server = vertx().createHttpServer();
    server.requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add(PermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(false, PermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(9876, "localhost");
    vertx().createHttpClient().getNow(9876, "localhost", "/?variable1=r2", res -> {
      server.close();
      if (res.failed()) {
        fail(res.cause());
        return;
      }
      testComplete();
    });
    await();
  }

}
