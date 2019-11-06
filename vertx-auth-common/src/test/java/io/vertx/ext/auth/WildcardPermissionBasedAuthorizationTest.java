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
import io.vertx.ext.auth.impl.WildcardPermissionBasedAuthorizationConverter;
import io.vertx.test.core.VertxTestBase;

public class WildcardPermissionBasedAuthorizationTest extends VertxTestBase {

  @Test
  public void testConverter() {
    TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1"),
        WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
    TestUtils.testJsonCodec(WildcardPermissionBasedAuthorization.create("wp1").setResource("resource"),
        WildcardPermissionBasedAuthorizationConverter::encode, WildcardPermissionBasedAuthorizationConverter::decode);
  }

  @Test
  public void testImplies1() {
    Assert.assertEquals(true,
        WildcardPermissionBasedAuthorization.create("wp1").verify(WildcardPermissionBasedAuthorization.create("wp1")));
  }

  @Test
  public void testImplies2() {
    Assert.assertEquals(true,
        WildcardPermissionBasedAuthorization.create("*").verify(WildcardPermissionBasedAuthorization.create("wp1")));
  }

  @Test
  public void testImplies3() {
    Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("printer:*")
        .verify(WildcardPermissionBasedAuthorization.create("printer:read")));
  }

  @Test
  public void testImplies4() {
    Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("*:read")
        .verify(WildcardPermissionBasedAuthorization.create("printer:read")));
  }

  @Test
  public void testImplies5() {
    Assert.assertEquals(true, WildcardPermissionBasedAuthorization.create("p1")
        .verify(WildcardPermissionBasedAuthorization.create("p1").setResource("r1")));
  }

  @Test
  public void testImplies6() {
    Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("p1").setResource("r1")
        .verify(WildcardPermissionBasedAuthorization.create("p1")));
  }

  @Test
  public void testImplies7() {
    Assert.assertEquals(false,
        WildcardPermissionBasedAuthorization.create("wp1").verify(WildcardPermissionBasedAuthorization.create("wp2")));
  }

  @Test
  public void testImplies8() {
    Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("printer:read")
        .verify(WildcardPermissionBasedAuthorization.create("*")));
  }

  @Test
  public void testImplies9() {
    Assert.assertEquals(false, WildcardPermissionBasedAuthorization.create("*:read")
        .verify(WildcardPermissionBasedAuthorization.create("printer:edit")));
  }

  @Test
  public void testMatch1() {
    vertx().createHttpServer().requestHandler(request -> {
      User user = User.create(new JsonObject().put("username", "dummy user"));
      user.authorizations().add(WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(true, WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
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
      user.authorizations().add(WildcardPermissionBasedAuthorization.create("p1").setResource("r1"));
      AuthorizationContext context = new AuthorizationContextImpl(user, request.params());
      assertEquals(false, WildcardPermissionBasedAuthorization.create("p1").setResource("{variable1}").match(context));
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
