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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class AuthorizationPolicyProviderTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void generatePolicy(TestContext should) {

    Authorization cashierShopAdmin = WildcardPermissionBasedAuthorization.create("txo.shop:*");
    Authorization cashierShopNl = WildcardPermissionBasedAuthorization.create("txo.shop:nl");
    Authorization cashierShopGlobalReader = WildcardPermissionBasedAuthorization.create("txo.shop:*").setResource("read");

    JsonObject policy = new JsonObject()
      .put("cashier-shop-admin", cashierShopAdmin.toJson())
      .put("cashier-shop-nl", cashierShopNl.toJson())
      .put("cashier-shop-global-reader", cashierShopGlobalReader.toJson());

    should.assertEquals(rule.vertx().fileSystem().readFileBlocking("authz-policy.json").toJson(), policy);
  }

  @Test
  public void testPolicy(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User paulo = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"paulo\",\n" +
        "  \"claims\" : [ \"cashier-shop-nl\" ]\n" +
        "}\n"
    ));

    // required authz
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }

  @Test
  public void testPolicyAdmin(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User admin = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"admin\",\n" +
        "  \"claims\" : [ \"cashier-shop-admin\" ]\n" +
        "}\n"
    ));

    // required authz
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(admin)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(admin);

        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }

  @Test
  public void testPolicyWithResource(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User reader = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"reader\",\n" +
        "  \"claims\" : [ \"cashier-shop-global-reader\" ]\n" +
        "}\n"
    ));

    // required authz, yet the resource is dynamic, it will be computed at runtime (later)
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl").setResource("{action}");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(reader)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(reader);
        // note that the authz doesn't know about the read resource, but we can use variables.
        // here we instruct that during evaluation, if a policy resource is looking for a variable {action} it should pick
        // the value "read".
        authorizationContext.variables().add("action", "read");

        // the user global reader will have the right action from the policy

        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }

  @Test
  public void testPolicyWithResourceAdmin(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User admin = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"admin\",\n" +
        "  \"claims\" : [ \"cashier-shop-admin\" ]\n" +
        "}\n"
    ));

    // required authz, yet the resource is dynamic, it will be computed at runtime (later)
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl").setResource("{action}");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(admin)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(admin);
        // note that the authz doesn't know about the read resource, but we can use variables.
        // here we instruct that during evaluation, if a policy resource is looking for a variable {action} it should pick
        // the value "read".
        authorizationContext.variables().add("action", "read");

        // the admin user has no restriction on resource so it will still be able to match
        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }

  @Test
  public void testPolicyWithMultipleValues(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("/claims", new JsonObject()
        .put("support-cashier", new JsonArray()
          .add(WildcardPermissionBasedAuthorization.create("txo.shop:*").toJson())
          .add(WildcardPermissionBasedAuthorization.create("view.cart:eu").toJson())));

    // same as policy:
    // {
    //   "support-cashier":
    //     [ {
    //       "type" : "wildcard",
    //       "permission" : "txo.shop:*"
    //       }, {
    //       "type" : "wildcard",
    //       "permission" : "view.cart:eu"
    //    } ]
    // }

    // This is a user that was decoded from a token...
    User paulo = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"paulo\",\n" +
        "  \"claims\" : [ \"support-cashier\" ]\n" +
        "}\n"
    ));

    // required authz (nl + view customer cart nl)
    Authorization authorization =
      AndAuthorization.create()
        .addAuthorization(WildcardPermissionBasedAuthorization.create("txo.shop:nl"))
        .addAuthorization(WildcardPermissionBasedAuthorization.create("view.cart:eu"));


    // simulate the authz flow
    policyAuthz
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }

  @Test
  public void testPolicyMissingClaims(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User paulo = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"paulo\"\n" +
        "}\n"
    ));

    // required authz
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

        if (authorization.match(authorizationContext)) {
          should.fail("Authorization should not match");
        } else {
          test.complete();
        }
      });
  }

  @Test
  public void testPolicyDeepClaims(TestContext should) throws Exception {

    final Async test = should.async();

    AuthorizationProvider policyAuthz = AuthorizationPolicyProvider
      .create("prop/claims", new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User paulo = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"paulo\",\n" +
        "  \"prop\" : {\n" +
        "    \"claims\" : [ \"cashier-shop-nl\" ]\n" +
        "  }\n" +
        "}\n"
    ));

    // required authz
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop:nl");

    // simulate the authz flow
    policyAuthz
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

        if (authorization.match(authorizationContext)) {
          test.complete();
        } else {
          should.fail("Authorization should match");
        }
      });
  }
}
