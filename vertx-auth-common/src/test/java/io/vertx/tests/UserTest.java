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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.*;
import io.vertx.ext.auth.impl.UserConverter;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class UserTest {

  private void testReadWriteUser(User user1) {
    JsonObject jsonUser1 = UserConverter.encode(user1);
    User user2 = UserConverter.decode(jsonUser1);
    Assert.assertEquals(user1, user2);
  }

  public User createTestUser() {
    return User.create(
      new JsonObject().put("principal1", "value principal 1").put("principal2", "value principal 2"),
      new JsonObject().put("attribute1", "value attribute 1").put("attribute2", "value attribute 2")
    );
  }

  @Test
  public void testReadWriteUser1() {
    // only principal
    User user = createTestUser();
    testReadWriteUser(user);
  }

  @Test
  public void testReadWriteUser2() {
    // principal + authorizations
    User user = createTestUser();
    User.create(new JsonObject().put("name", "name1").put("value1", "a value"));
    user.authorizations()
      .put(
        "providerId",
        PermissionBasedAuthorization.create("permission1"),
        RoleBasedAuthorization.create("role1"),
        WildcardPermissionBasedAuthorization.create("orders:edit:1234"),
        WildcardPermissionBasedAuthorization.create("billing:*"),
        NotAuthorization.create(PermissionBasedAuthorization.create("permission1")),
        AndAuthorization.create(),
        AndAuthorization.create()
          .addAuthorization(PermissionBasedAuthorization.create("permission1"))
          .addAuthorization(RoleBasedAuthorization.create("role1"))
          .addAuthorization(PermissionBasedAuthorization.create("permission2"))
          .addAuthorization(RoleBasedAuthorization.create("role2")),
        OrAuthorization.create(),
        OrAuthorization.create()
          .addAuthorization(PermissionBasedAuthorization.create("permission1"))
          .addAuthorization(RoleBasedAuthorization.create("role1"))
          .addAuthorization(PermissionBasedAuthorization.create("permission2"))
          .addAuthorization(RoleBasedAuthorization.create("role2")));
    testReadWriteUser(user);
  }

  @Test
  public void testReadWriteUser3() {
    // principal + authorizations + attributes
    User user = createTestUser();
    user.authorizations().put("providerId",
      RoleBasedAuthorization.create("role1"),
      RoleBasedAuthorization.create("role2"));

    testReadWriteUser(user);
  }

  @Test
  public void testUniqueAuthorizations() {
    // principal + authorizations
    User user = createTestUser();
    Set<Authorization> authorizations = new HashSet<>();

    authorizations.add(PermissionBasedAuthorization.create("permission1"));
    authorizations.add(PermissionBasedAuthorization.create("permission1"));
    authorizations.add(RoleBasedAuthorization.create("role1"));
    authorizations.add(RoleBasedAuthorization.create("role1"));

    user.authorizations().put("providerId", authorizations);
    final AtomicInteger cnt = new AtomicInteger();
    user.authorizations().forEach("providerId", auth -> cnt.incrementAndGet());
    Assert.assertEquals(2, cnt.get());
  }

  @Test
  public void simpleGet() {
    User user = User.create(
      new JsonObject().put("access_token", "jwt"),
      new JsonObject()
        .put("rootClaim", "accessToken")
        .put("accessToken",
          new JsonObject(
            "{\n" +
              "      \"iss\": \"https://server.example.com\",\n" +
              "      \"aud\": \"s6BhdRkqt3\",\n" +
              "      \"jti\": \"a-123\",\n" +
              "      \"exp\": 999999999999,\n" +
              "      \"iat\": 1311280970,\n" +
              "      \"sub\": \"24400320\",\n" +
              "      \"upn\": \"jdoe@server.example.com\",\n" +
              "      \"groups\": [\"red-group\", \"green-group\", \"admin-group\", \"admin\"]\n" +
              "}")));

    assertNotNull(user.get("groups"));
    JsonArray groups = user.get("groups");
    assertEquals(4, groups.size());
  }

  @Test
  public void testMerge() {
    User userA, userB;

    userA = User.create(new JsonObject().put("access_token", "A"), new JsonObject().put("roles", new JsonArray().add("read")));
    userB = User.create(new JsonObject().put("access_token", "B"), new JsonObject().put("roles", new JsonArray().add("write")));

    userA.merge(userB);

    // expectation
    assertEquals("B", userA.principal().getString("access_token"));
    assertEquals(new JsonArray().add("read").add("write"), userA.attributes().getJsonArray("roles"));

    // same can be said if both values are plain strings

    userA = User.create(new JsonObject().put("access_token", "A"), new JsonObject().put("roles", "read"));
    userB = User.create(new JsonObject().put("access_token", "B"), new JsonObject().put("roles", "write"));

    userA.merge(userB);

    // expectation
    assertEquals("B", userA.principal().getString("access_token"));
    assertEquals(new JsonArray().add("read").add("write"), userA.attributes().getJsonArray("roles"));

    // or 1st is array already

    userA = User.create(new JsonObject().put("access_token", "A"), new JsonObject().put("roles", new JsonArray().add("read")));
    userB = User.create(new JsonObject().put("access_token", "B"), new JsonObject().put("roles", "write"));

    userA.merge(userB);

    // expectation
    assertEquals("B", userA.principal().getString("access_token"));
    assertEquals(new JsonArray().add("read").add("write"), userA.attributes().getJsonArray("roles"));

    // or 2nd is array already

    userA = User.create(new JsonObject().put("access_token", "A"), new JsonObject().put("roles", "read"));
    userB = User.create(new JsonObject().put("access_token", "B"), new JsonObject().put("roles", new JsonArray().add("write")));

    userA.merge(userB);

    // expectation
    assertEquals("B", userA.principal().getString("access_token"));
    assertEquals(new JsonArray().add("read").add("write"), userA.attributes().getJsonArray("roles"));
  }

  @Test
  public void testMergeAmr() {
    User userA, userB;

    userA = User.fromName("a");
    userB = User.fromName("b");

    userA.principal().put("amr", Collections.singletonList("pwd"));
    userB.principal().put("amr", Collections.singletonList("pwd"));

    userA.merge(userB);

    // expectation
    assertTrue(userA.hasAmr("pwd"));
    assertTrue(userA.hasAmr("mfa"));
    assertFalse(userB.hasAmr("mfa"));

    // Test #2 (B) has no amr

    userA = User.fromName("a");
    userB = User.fromName("b");

    userA.principal().put("amr", Collections.singletonList("pwd"));

    userA.merge(userB);

    // expectation
    assertTrue(userA.hasAmr("pwd"));
    assertTrue(userA.hasAmr("mfa"));
    assertFalse(userB.hasAmr("mfa"));

    // Test #3 (A) has no amr

    userA = User.fromName("a");
    userB = User.fromName("b");

    userA.principal().put("amr", Collections.singletonList("pwd"));

    userA.merge(userB);

    // expectation
    assertTrue(userA.hasAmr("pwd"));
    assertTrue(userA.hasAmr("mfa"));
    assertFalse(userB.hasAmr("mfa"));

    // Test #4 (A and B) has no amr

    userA = User.fromName("a");
    userB = User.fromName("b");

    userA.merge(userB);

    // expectation
    assertTrue(userA.hasAmr("mfa"));
    assertFalse(userB.hasAmr("mfa"));
  }
}
