/*
 * Copyright 2014 Red Hat, Inc.
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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthorization;
import io.vertx.ext.auth.mongo.MongoAuthorizationOptions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.model.InitializationError;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Testing MongoAuth with no encryption for the user password
 *
 * @author mremme
 */

public class MongoAuthorizationTest extends MongoAuthenticationTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthorizationTest.class);

  protected MongoAuthorization authorizationProvider;
  protected MongoAuthorizationOptions authorizationOptions = new MongoAuthorizationOptions();

  @Override
  public void setUp() throws Exception {
    super.setUp();
    getMongoClient(); // note: also drop existing collections
  }

  @Before
  public void initTestUsers() throws Exception {
    log.info("initTestUsers");
    List<InternalUser> users = createUserList();
    CountDownLatch latch = new CountDownLatch(users.size());

    for (InternalUser user : users) {
      if (!initOneUser(user, latch))
        throw new InitializationError("could not create users");
    }
    awaitLatch(latch);
    if (!verifyUserData(authenticationOptions))
      throw new InitializationError("users weren't created");

  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  protected MongoAuthorization getAuthorizationProvider() {
    if (authorizationProvider == null) {
      MongoAuthorizationOptions options = new MongoAuthorizationOptions();
      try {
        authorizationProvider = MongoAuthorization.create("id", getMongoClient(), options);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
    return authorizationProvider;
  }

  @Test
  public void testAuthoriseHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authenticationOptions.getUsernameField(), "tim").put(authenticationOptions.getPasswordField(), "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, onSuccess(has -> {
        assertTrue(RoleBasedAuthorization.create("developer").match(user));
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authenticationOptions.getUsernameField(), "tim").put(authenticationOptions.getPasswordField(), "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, onSuccess(has -> {
        assertFalse(RoleBasedAuthorization.create("manager").match(user));
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authenticationOptions.getUsernameField(), "tim").put(authenticationOptions.getPasswordField(), "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, onSuccess(has -> {
        assertTrue(PermissionBasedAuthorization.create("commit_code").match(user));
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authenticationOptions.getUsernameField(), "tim").put(authenticationOptions.getPasswordField(), "sausages");
    getAuthenticationProvider().authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      fillUserAuthorizations(user, onSuccess(has -> {
        assertFalse(PermissionBasedAuthorization.create("eat_sandwich").match(user));
        testComplete();
      }));
    }));
    await();
  }

  /*
   * ################################################## preparation methods
   * ##################################################
   */
  private List<InternalUser> createUserList() {
    List<InternalUser> users = new ArrayList<>();
    users.add(new InternalUser("Michael", "ps1", null, null));
    users.add(new InternalUser("Doublette", "ps1", null, null));
    users.add(new InternalUser("Doublette", "ps2", null, null));
    users.add(new InternalUser("Doublette", "ps2", null, null));

    users.add(new InternalUser("tim", "sausages", Arrays.asList("morris_dancer", "superadmin", "developer"), Arrays
        .asList("commit_code", "merge_pr", "do_actual_work", "bang_sticks")));
    return users;
  }

  @Override
  protected void dropCollections(CountDownLatch latch) {
    super.dropCollections(latch);
  }

  private boolean initOneUser(InternalUser user, CountDownLatch latch) throws Exception {
    CountDownLatch intLatch = new CountDownLatch(1);
    final StringBuffer buffer = new StringBuffer();

    insertUser(getAuthenticationProvider(), authenticationOptions, user.username, user.password)
      .compose(res -> insertAuth(user.username, user.roles, user.permissions)
      ).setHandler(res -> {
      if (res.succeeded()) {
        log.info("user added: " + user.username);
        latch.countDown();
      } else {
        log.error("", res.cause());
        buffer.append("false");
      }
      intLatch.countDown();
    });
    awaitLatch(intLatch);
    return buffer.length() == 0;
  }



  private void fillUserAuthorizations(User user, Handler<AsyncResult<Void>> handler) {
    getAuthorizationProvider().getAuthorizations(user, handler);
  }

  public Future<String> insertAuth(String username, List<String> roles, List<String> permissions) {

    JsonObject user = new JsonObject();
    user.put(authorizationOptions.getUsernameField(), username);
    user.put(authorizationOptions.getRoleField(), roles);
    user.put(authorizationOptions.getPermissionField(), permissions);

    Promise promise = Promise.promise();
    try {
      getMongoClient().save(authorizationOptions.getCollectionName(), user, promise);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return promise.future();
  }

  private class InternalUser {
    String username;
    String password;
    List<String> roles;
    List<String> permissions;

    InternalUser(String username, String password, List<String> roles, List<String> permissions) {
      this.username = username;
      this.password = password;
      this.roles = roles;
      this.permissions = permissions;

    }

  }
}
