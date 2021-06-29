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

package io.vertx.ext.auth.otp.hotp;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.otp.Authenticator;
import io.vertx.ext.auth.otp.DummyDatabase;
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
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test valid auth code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      long counter = user1.get("counter");
      should.assertEquals(1L, counter);
      Integer authAttempt = user1.get("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }

  @Test
  public void testHotp2(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test use valid auth code after invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

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
      long counter = user1.get("counter");
      should.assertEquals(1L, counter);
      int authAttempt = user1.get("auth_attempts");
      should.assertEquals(2, authAttempt);
    }));
  }

  @Test
  public void testHotp3(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(5));
// Test use valid auth code after several invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

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
      long counter = user1.get("counter");
      should.assertEquals(6L, counter);
      int authAttempt = user1.get("auth_attempts");
      should.assertEquals(4, authAttempt);
    }));
  }

  @Test
  public void testHotp4(TestContext should) {
    final DummyDatabase db = new DummyDatabase();
    // Test valid auth code without require auth

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "651075");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp5(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test valid auth code and repeated auth previous code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(user1 -> {
      long counter = user1.get("counter");
      should.assertEquals(1L, counter);
      Integer authAttempt = user1.get("auth_attempt");
      should.assertNull(authAttempt);
    }));

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp6(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test valid auth code after revoke hotp

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "651075");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp7(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(7))
      .fixture(new Authenticator().setIdentifier("user2").setKey(USER2_KEY).setCounter(3));
    // test valid auth code for several users

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject user1Credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "974712");

    authProvider.authenticate(user1Credentials, should.asyncAssertSuccess(user -> {
      long counter = user.get("counter");
      should.assertEquals(8L, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));

    JsonObject user2Credentials = new JsonObject()
      .put("identifier", "user2")
      .put("code", "054804");

    authProvider.authenticate(user2Credentials, should.asyncAssertSuccess(user -> {
      long counter = user.get("counter");
      should.assertEquals(4L, counter);
      Integer authAttempt = user.get("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }

  @Test
  public void testHotp8(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(7))
      .fixture(new Authenticator().setIdentifier("user2").setKey(USER2_KEY).setCounter(3));
    // test valid authorization code for the first user

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject user1Credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "974712");

    authProvider.authenticate(user1Credentials, should.asyncAssertSuccess(user -> {
      long counter = user.get("counter");
      should.assertEquals(8L, counter);
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
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test valid auth code and unexpected password length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(8);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "698956");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp10(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test auth with unexpected code length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(6);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "29403113451");

    authProvider.authenticate(credentials, should.asyncAssertFailure());
  }

  @Test
  public void testHotp12(TestContext should) {
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(0));
    // Test invalid auth code with attempts limit

    final int attemptsLimit = 3;
    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setAuthAttemptsLimit(attemptsLimit);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

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
    final DummyDatabase db = new DummyDatabase()
      .fixture(new Authenticator().setIdentifier("user1").setKey(USER1_KEY).setCounter(8));
    // Test valid auth code with using resynchronization

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setLookAheadWindow(5);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions)
      .authenticatorFetcher(db::fetch)
      .authenticatorUpdater(db::upsert);

    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "203646");

    authProvider.authenticate(credentials, should.asyncAssertSuccess(res -> {
      long counter = res.get("counter");
      should.assertEquals(11L, counter);
      Integer authAttempt = res.get("auth_attempt");
      should.assertNull(authAttempt);
    }));
  }
}
