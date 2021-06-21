/*
 * Copyright (c) 2021 Dmitry Novikov
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.ext.auth.otp;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class HotpAuthTest {

  private static final String USER1_KEY = "SRF6EYYCC6SNJEQD4VDZDZPGMODFPCSL";
  private static final String USER2_KEY = "OK7JVNHJO5ZMC57QLYJ6QNTOZFKVN76Y";

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testHotp1(TestContext should) {
    // Test valid auth code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);
    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      int counter = user1.attributes().getInteger("counter");
      should.assertEquals(1, counter);
      Integer authAttempt = user1.attributes().getInteger("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }

  @Test
  public void testHotp2(TestContext should) {
    // Test use valid auth code after invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    // Attempt auth with invalid code
    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "718330");

    authProvider.authenticate(credentials, should.asyncAssertFailure());

    // attempt auth with valid code
    credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      int counter = user1.get("counter");
      should.assertEquals(1, counter);
      int authAttempt = user1.get("auth_attempts");
      should.assertEquals(2, authAttempt);
    }));
  }

  @Test
  public void testHotp3(TestContext should) {
    // Test use valid auth code after several invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 5);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    // Attempt auth with invalid code
    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "296103");

    authProvider.authenticate(credentials, should.asyncAssertFailure());

    // Attempt auth with invalid code
    credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "571931");

    authProvider.authenticate(credentials, should.asyncAssertFailure());

    // Attempt auth with invalid code
    credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "881695");

    authProvider.authenticate(credentials, should.asyncAssertFailure());

    // Attempt auth with valid code
    credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "142559");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      int counter = user1.get("counter");
      should.assertEquals(6, counter);
      int authAttempt = user1.get("auth_attempts");
      should.assertEquals(4, authAttempt);
    }));
  }

  @Test
  public void testHotp4(TestContext should) {
    // Test valid auth code without require auth

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "651075");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp5(TestContext should) {
    // Test valid auth code and repeated auth previous code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      int counter = user1.attributes().getInteger("counter");
      should.assertEquals(1, counter);
      Integer authAttempt = user1.get("auth_attempt");
      should.assertNull(authAttempt);
    }));

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp6(TestContext should) {
    // Test valid auth code after revoke hotp

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    authProvider.revokeHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "651075");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp7(TestContext should) {
    // test valid auth code for several users

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject user1Principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 7);

    User user1 = User.create(user1Principal);
    authProvider.requestHotp(user1, should.asyncAssertSuccess());

    JsonObject user2Principal = new JsonObject()
      .put("identifier", "user2")
      .put("key", USER2_KEY)
      .put("counter", 3);

    User user2 = User.create(user2Principal);
    authProvider.requestHotp(user2, should.asyncAssertSuccess());

    JsonObject user1Credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "974712");

    authProvider.authenticate(user1Credentials, should.asyncAssertSuccess(user -> {
      int counter = user.attributes().getInteger("counter");
      should.assertEquals(8, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));

    JsonObject user2Credentials = new JsonObject()
      .put("identifier", "user2")
      .put("code", "054804");

    authProvider.authenticate(user2Credentials, should.asyncAssertSuccess(user -> {
      int counter = user.attributes().getInteger("counter");
      should.assertEquals(4, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }

  @Test
  public void testHotp8(TestContext should) {
    // test valid authorization code for the first user

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject user1Principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 7);

    User user1 = User.create(user1Principal);
    authProvider.requestHotp(user1, should.asyncAssertSuccess());

    JsonObject user2Principal = new JsonObject()
      .put("identifier", "user2")
      .put("key", USER2_KEY)
      .put("counter", 3);

    User user2 = User.create(user2Principal);
    authProvider.requestHotp(user2, should.asyncAssertSuccess());

    JsonObject user1Credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "974712");

    authProvider.authenticate(user1Credentials, should.asyncAssertSuccess(user -> {
      int counter = user.attributes().getInteger("counter");
      should.assertEquals(8, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));

    JsonObject user2Credentials = new JsonObject()
      .put("identifier", "user2")
      .put("code", "302344");

    authProvider.authenticate(user2Credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp9(TestContext should) {
    // Test valid auth code and unexpected password length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(8);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp10(TestContext should) {
    // Test auth with unexpected code length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(6);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "29403113451");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp11(TestContext should) {
    // Test request code and auth attempts limit

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setAuthAttemptsLimit(5);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 6);

    final JsonObject attributes = new JsonObject()
      .put("attempts_limit", 8);

    User user = User.create(principal, attributes);

    authProvider.requestHotp(user, should.asyncAssertSuccess());
  }

  @Test
  public void testHotp12(TestContext should) {
    // Test invalid auth code with attempts limit

    final int attemptsLimit = 3;
    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setAuthAttemptsLimit(attemptsLimit);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 0);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "738419");

    for (int i = 0; i < 10; i++) {
      int finalI = i;
      authProvider.authenticate(credentials, res -> {
        if (res.succeeded()) {
          should.fail();
        } else {
          if (finalI >= attemptsLimit) {
            should.assertNotNull(res.cause());
          }
        }
      });
    }
  }

  @Test
  public void testHotp13(TestContext should) {
    // Test valid auth code with using resynchronization

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setLookAheadWindow(5);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", USER1_KEY)
      .put("counter", 8);

    User user = User.create(principal);

    authProvider.requestHotp(user, should.asyncAssertSuccess());

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "203646");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(res -> {
      int counter = user.attributes().getInteger("counter");
      should.assertEquals(11, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }
}
