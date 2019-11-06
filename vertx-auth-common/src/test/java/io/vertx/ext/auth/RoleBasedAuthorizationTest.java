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

import org.junit.Assert;
import org.junit.Test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthorizationContextImpl;
import io.vertx.ext.auth.impl.RoleBasedAuthorizationConverter;
import io.vertx.test.core.VertxTestBase;

public class RoleBasedAuthorizationTest extends VertxTestBase {

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1"), RoleBasedAuthorizationConverter::encode,
        RoleBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(RoleBasedAuthorization.create("role1").setResource("resource"),
        RoleBasedAuthorizationConverter::encode, RoleBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    Assert.assertEquals(true, RoleBasedAuthorization.create("role1").verify(RoleBasedAuthorization.create("role1")));
  }

  @Test
  public void testImplies2() {
    Assert.assertEquals(true, RoleBasedAuthorization.create("p1").setResource("r1")
        .verify(RoleBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies3() {
    Assert.assertEquals(false,
        RoleBasedAuthorization.create("p1").setResource("r1").verify(RoleBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies4() {
    Assert.assertEquals(false,
        RoleBasedAuthorization.create("p1").verify(RoleBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies5() {
    Assert.assertEquals(false, RoleBasedAuthorization.create("role1").verify(RoleBasedAuthorization.create("role2")));
  }

  @Test
  public void testMatch1() {
    vertx().createHttpServer().requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add(RoleBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(true, RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(9876, "localhost");
    vertx().createHttpClient().getNow(9876, "localhost", "/?variable1=r1", res -> {
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
    vertx().createHttpServer().requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add(RoleBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(false, RoleBasedAuthorization.create("p1").setResource("{variable1}").match(context));
      request.response().end();
    }).listen(9876, "localhost");
    vertx().createHttpClient().getNow(9876, "localhost", "/?variable1=r2", res -> {
      if (res.failed()) {
        fail(res.cause());
        return;
      }
      testComplete();
    });
    await();
  }

}
