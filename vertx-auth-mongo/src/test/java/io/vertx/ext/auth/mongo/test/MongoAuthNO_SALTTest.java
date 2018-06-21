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

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.mongo.AuthenticationException;
import io.vertx.ext.auth.mongo.MongoAuth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.junit.Test;
import org.junit.runners.model.InitializationError;

/**
 * Testing MongoAuth with no encryption for the user password
 *
 * @author mremme
 */

public class MongoAuthNO_SALTTest extends MongoBaseTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthNO_SALTTest.class);

  protected MongoAuth authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    getMongoClient();
    initAuthService();
    initDemoData();
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  @Test
  public void testAuthenticate() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadPwd() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "eggs");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertTrue(v instanceof AuthenticationException);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadUser() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "blah").put(authProvider.getPasswordField(), "whatever");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertTrue(v instanceof AuthenticationException);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthoriseHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorized("role:developer", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorized("role:manager", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorized("commit_code", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorized("eat_sandwich", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }

  /*
   * ################################################## preparation methods
   * ##################################################
   */
  protected List<InternalUser> createUserList() {
    List<InternalUser> users = new ArrayList<>();
    users.add(new InternalUser("Michael", "ps1", null, null));
    users.add(new InternalUser("Doublette", "ps1", null, null));
    users.add(new InternalUser("Doublette", "ps2", null, null));
    users.add(new InternalUser("Doublette", "ps2", null, null));

    users.add(new InternalUser("tim", "sausages", Arrays.asList("morris_dancer", "superadmin", "developer"), Arrays
        .asList("commit_code", "merge_pr", "do_actual_work", "bang_sticks")));
    return users;
  }

  protected void initAuthService() throws Exception {
    if (authProvider == null) {
      log.info("initAuthService");
      authProvider = createProvider();
    }
  }

  protected MongoAuth createProvider() throws Exception {
    JsonObject config = new JsonObject();
    config.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
    return MongoAuth.create(getMongoClient(), config);
  }

  @Override
  public void initDemoData() throws Exception {
    initTestUsers();
  }

  private void initTestUsers() throws Exception {
    log.info("initTestUsers");
    List<InternalUser> users = createUserList();
    CountDownLatch latch = new CountDownLatch(users.size());

    for (InternalUser user : users) {
      if (!initOneUser(user, latch))
        throw new InitializationError("could not create users");
    }
    awaitLatch(latch);
    if (!verifyUserData())
      throw new InitializationError("users weren't created");

  }

  private boolean verifyUserData() throws Exception {
    final StringBuffer buffer = new StringBuffer();
    CountDownLatch intLatch = new CountDownLatch(1);
    String collectionName = authProvider.getCollectionName();
    log.info("verifyUserData in " + collectionName);
    getMongoClient().find(collectionName, new JsonObject(), res -> {
      if (res.succeeded()) {
        log.info(res.result().size() + " users found: " + res.result());

      } else {
        log.error("", res.cause());
        buffer.append("false");
      }
      intLatch.countDown();
    });
    awaitLatch(intLatch);
    return buffer.length() == 0;
  }

  /**
   * Creates a user inside mongo. Returns true, if user was successfully added
   *
   * @param user
   * @param latch
   * @return
   * @throws Exception
   * @throws Throwable
   */
  private boolean initOneUser(InternalUser user, CountDownLatch latch) throws Exception {
    CountDownLatch intLatch = new CountDownLatch(1);
    final StringBuffer buffer = new StringBuffer();

    authProvider.insertUser(user.username, user.password, user.roles, user.permissions, res -> {
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

  /**
   * Creates JsonObject for login in the convenient way
   *
   * @param username
   *          the username to be used
   * @param password
   *          the password to be used
   * @return a {@link JsonObject} with valid parameters
   */
  public JsonObject createAuthInfo(String username, String password) {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), username).put(authProvider.getPasswordField(), password);
    return authInfo;
  }

  class InternalUser {
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
