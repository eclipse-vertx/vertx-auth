/*
 * Copyright 2020 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo.test;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.*;
import io.vertx.ext.mongo.MongoClient;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class MongoUserUtilTest extends MongoBaseTest {

  @Test
  public void createUserSmokeTest() throws Throwable {
    MongoClient mongoClient = this.getMongoClient();
    MongoAuthentication authProvider = MongoAuthentication.create(mongoClient, new MongoAuthenticationOptions());
    MongoUserUtil userUtil = MongoUserUtil.create(mongoClient);
    userUtil.createUser("foo", "bar")
      .flatMap(id -> {
        assertTrue(id.length() > 0);
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("foo", "bar");
        return authProvider.authenticate(credentials);
      })
      .onFailure(this::fail)
      .onSuccess(user -> {
        assertEquals("foo", user.principal().getString("username"));
        this.complete();
      });
    await();
  }

  @Test
  public void createUserAndPermissionsTest() throws Throwable {
    MongoClient mongoClient = this.getMongoClient();
    MongoAuthentication authnProvider = MongoAuthentication.create(mongoClient, new MongoAuthenticationOptions());
    MongoAuthorization authzProvider = MongoAuthorization.create("abc", mongoClient, new MongoAuthorizationOptions());
    MongoUserUtil userUtil = MongoUserUtil.create(mongoClient);
    List<String> roles = Arrays.asList("a", "b");
    List<String> perms = Arrays.asList("c", "d");
    JsonObject credentials = new JsonObject()
      .put("username", "fizz")
      .put("password", "buzz");
    userUtil
      .createUser("fizz", "buzz")
      .flatMap(id -> userUtil.createUserRolesAndPermissions("fizz", roles, perms))
      .flatMap(id -> authnProvider.authenticate(credentials))
      .flatMap(user -> authzProvider.getAuthorizations(user).map(v -> user))
      .onFailure(this::fail)
      .onSuccess(user -> {
        Set<Authorization> auths = user.authorizations().get("abc");
        assertTrue(auths.contains(RoleBasedAuthorization.create("a")));
        assertTrue(auths.contains(RoleBasedAuthorization.create("b")));
        assertFalse(auths.contains(RoleBasedAuthorization.create("c")));
        assertTrue(auths.contains(PermissionBasedAuthorization.create("c")));
        assertTrue(auths.contains(PermissionBasedAuthorization.create("d")));
        assertFalse(auths.contains(PermissionBasedAuthorization.create("e")));
        this.complete();
      });
    await();
  }
}
