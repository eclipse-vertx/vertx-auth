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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.Permission;
import java.util.HashSet;
import java.util.Set;

@RunWith(VertxUnitRunner.class)
public class AuthorizationPolicyProviderTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  final AuthorizationProvider dummy = new AuthorizationPolicyProvider() {
    @Override
    public String getId() {
      return "dummy";
    }

    @Override
    public void getAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
      // collect the authorizations from the user attributes and convert them to Authorizations according to the policy
      JsonArray claims = user.getOrDefault("claims", new JsonArray());
      Set<Authorization> authzs = new HashSet<>();
      for (Object claim : claims) {
        authzs.add(WildcardPermissionBasedAuthorization.create(claim.toString()));
      }
      user.authorizations().add(getId(), authzs);
      handler.handle(Future.succeededFuture());
    }
  };


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
      .create(dummy, new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

    // This is a user that was decoded from a token...
    User paulo = User.create(new JsonObject(
      "{\n" +
        "  \"sub\" : \"paulo\",\n" +
        "  \"claims\" : [ \"cashier-shop-nl\" ]\n" +
        "}\n"
    ));

    // required authz
    Authorization authorization = WildcardPermissionBasedAuthorization.create("txo.shop=nl");

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
      .create(dummy, new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

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
      .create(dummy, new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

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
      .create(dummy, new JsonObject(rule.vertx().fileSystem().readFileBlocking("authz-policy.json")));

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
}
