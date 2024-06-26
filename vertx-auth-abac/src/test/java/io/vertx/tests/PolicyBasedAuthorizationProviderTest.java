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
package io.vertx.tests;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.abac.Attribute;
import io.vertx.ext.auth.abac.Policy;
import io.vertx.ext.auth.abac.PolicyBasedAuthorizationProvider;
import io.vertx.ext.auth.authorization.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(VertxUnitRunner.class)
public class PolicyBasedAuthorizationProviderTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private List<Policy> policies() {
    return Arrays.asList(
      // every user can read the web resource /public
      new Policy()
        .setName("public")
        .addAuthorization(WildcardPermissionBasedAuthorization.create("web:GET").setResource("/public")),
      // supplier can create resource /public
      new Policy()
        .setName("suppliers")
        .addSubject("supplier")
        .addAuthorization(WildcardPermissionBasedAuthorization.create("web:POST").setResource("/public")),
      // admin can do anything on /public
      new Policy()
        .setName("administrator")
        .addSubject("admin")
        .addAuthorization(WildcardPermissionBasedAuthorization.create("web:*").setResource("/public")),
      // "paulo" user has role EU can read on /gdpr
      new Policy()
        .setName("EU users")
        .addSubject("paulo")
        .addSubject("morre")
        .addAuthorization(RoleBasedAuthorization.create("EU"))
        .addAuthorization(WildcardPermissionBasedAuthorization.create("web:GET").setResource("/gdpr")));
  }

  @Test
  public void generatePolicy(TestContext should) {

    PolicyBasedAuthorizationProvider provider = PolicyBasedAuthorizationProvider.create();
    provider.setPolicies(policies());

    JsonArray array = new JsonArray();
    policies().forEach(policy -> array.add(policy.toJson()));

    System.out.println(array.encodePrettily());
  }

  @Test
  public void testPolicyAdmin(TestContext should) throws Exception {

    final Async test = should.async();

    final AuthorizationProvider abac = PolicyBasedAuthorizationProvider.create()
      .setPolicies(policies());

    // This is a user that, for example, was decoded from a token...
    User paulo = User.fromName("admin");

    // required authz (this should be created by the application at runtime.
    // instead of having a well-known authorization, the application can create
    // a dynamic authorization based on the current context)
    final String domain = "web";
    final String operation = "DELETE";

    final List<Authorization> requirements = Arrays.asList(
      WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/public"),
      WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/private")
    );

    // simulate the authz flow
    abac
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // perform the requirements checks
        for (int i = 0; i < requirements.size(); i++) {
          Authorization requirement = requirements.get(i);

          // create the authorization context
          final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

          // check if the authorization matches
          System.out.println("requirement: " + requirement + " matches: " + requirement.match(authorizationContext));

          switch (i) {
            case 0:
              // admin can do any operation on /public
              should.assertTrue(requirement.match(authorizationContext));
              break;
            case 1:
              // admin cannot do any operation on /private
              should.assertFalse(requirement.match(authorizationContext));
              break;
          }
        }
        test.complete();
      });
  }

  @Test
  public void testPolicy(TestContext should) throws Exception {
    final Async test = should.async();

    final AuthorizationProvider abac = PolicyBasedAuthorizationProvider.create()
      .setPolicies(policies());

    // This is a user that, for example, was decoded from a token...
    User paulo = User.fromName("paulo");

    // required authz (this should be created by the application at runtime.
    // instead of having a well-known authorization, the application can create
    // a dynamic authorization based on the current context)
    final String domain = "web";
    final String operation = "GET";

    final List<Authorization> requirements = Arrays.asList(
      WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/public"),
      WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/gdpr"),
      WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/private"),
      // paulo cannot post
      WildcardPermissionBasedAuthorization.create(domain + ":POST").setResource("/public")
    );

    // simulate the authz flow
    abac
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // validation

        // we know that initially there are 5 (4 declared + 1 with multiple values) policies, but 2 shall not be
        // applicable: "admin", "supplier"
        final AtomicInteger count = new AtomicInteger(0);
        paulo.authorizations().forEach((providerId, authorization) -> {
          System.out.println(providerId + " -> " + authorization);
          count.incrementAndGet();
        });

        should.assertEquals(3, count.get());

        // perform the requirements checks
        for (int i = 0; i < requirements.size(); i++) {
          Authorization requirement = requirements.get(i);

          // create the authorization context
          final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);

          // check if the authorization matches
          System.out.println("requirement: " + requirement + " matches: " + requirement.match(authorizationContext));

          switch (i) {
            case 0:
              // any user can access public (paulo is any user)
              should.assertTrue(requirement.match(authorizationContext));
              break;
            case 1:
              // only users with role EU can access gdpr (paulo is EU)
              should.assertTrue(requirement.match(authorizationContext));
              break;
            case 2:
              // no one was allowed to access private
              should.assertFalse(requirement.match(authorizationContext));
              break;
            case 3:
              // paulo isn't a supplier so no POST
              should.assertFalse(requirement.match(authorizationContext));
              break;
          }
        }
      })
      .onSuccess(v -> test.complete());
  }

  @Test
  public void testEUPolicyWithoutRoleButAttribute(TestContext should) throws Exception {
    final Async test = should.async();

    final AuthorizationProvider abac = PolicyBasedAuthorizationProvider.create()
      .addPolicy(
        // any user has role EU can read on /gdpr
        new Policy()
          .setName("EU users")
          .addAttribute(Attribute.has("/attributes/location", "EU"))
          .addAuthorization(WildcardPermissionBasedAuthorization.create("web:GET").setResource("/gdpr")));

    // This is a user that, for example, was decoded from a token...
    User paulo = User.fromName("paulo");

    // required authz (this should be created by the application at runtime.
    // instead of having a well-known authorization, the application can create
    // a dynamic authorization based on the current context)
    final String domain = "web";
    final String operation = "GET";

    Authorization requirement = WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/gdpr");

    // simulate the authz flow
    abac
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);
        // check if the authorization matches
        System.out.println("requirement: " + requirement + " matches: " + requirement.match(authorizationContext));
        should.assertFalse(requirement.match(authorizationContext));
      })
      .onSuccess(v -> test.complete());
  }

  @Test
  public void testEUPolicyWithoutRoleButAttributeNOK(TestContext should) throws Exception {
    final Async test = should.async();

    final AuthorizationProvider abac = PolicyBasedAuthorizationProvider.create()
      .addPolicy(
        // any user has role EU can read on /gdpr
        new Policy()
          .setName("EU users")
          .addAttribute(Attribute.eq("/attributes/location", "EU"))
          .addAuthorization(WildcardPermissionBasedAuthorization.create("web:GET").setResource("/gdpr")));

    // This is a user that, for example, was decoded from a token...
    User paulo = User.fromName("paulo");
    // this user is now tagged
    paulo.attributes().put("location", "EU");

    // required authz (this should be created by the application at runtime.
    // instead of having a well-known authorization, the application can create
    // a dynamic authorization based on the current context)
    final String domain = "web";
    final String operation = "GET";

    Authorization requirement = WildcardPermissionBasedAuthorization.create(domain + ":" + operation).setResource("/gdpr");

    // simulate the authz flow
    abac
      .getAuthorizations(paulo)
      .onFailure(should::fail)
      .onSuccess(v -> {
        // create the authorization context
        final AuthorizationContext authorizationContext = AuthorizationContext.create(paulo);
        // check if the authorization matches
        System.out.println("requirement: " + requirement + " matches: " + requirement.match(authorizationContext));
        should.assertTrue(requirement.match(authorizationContext));
      })
      .onSuccess(v -> test.complete());
  }
}
