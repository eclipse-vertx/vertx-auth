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
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class HotpAuthTest extends VertxTestBase {

  private static final String USER1_KEY = "SRF6EYYCC6SNJEQD4VDZDZPGMODFPCSL";
  private static final String USER2_KEY = "OK7JVNHJO5ZMC57QLYJ6QNTOZFKVN76Y";

  @Test
  public void testHotp1() {
    // Test valid auth code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "698956");
    }};
    authProvider.authenticate(credentials, onSuccess(user1 -> {
      int counter = user1.attributes().getInteger("counter");
      assertEquals(1, counter);
      Integer authAttempt = user1.get("auth_attempt");
      assertNull(authAttempt);
      testComplete();
    }));
  }

  @Test
  public void testHotp2() {
    // Test use valid auth code after invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    // Attempt auth with invalid code
    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "718330");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });

    // attempt auth with valid code
    credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "698956");
    }};
    authProvider.authenticate(credentials, onSuccess(user1 -> {
      long counter = user1.get("counter");
      assertEquals(1, counter);
      long authAttempt = user1.get("auth_attempts");
      assertEquals(2, authAttempt);
      testComplete();
    }));
  }

  @Test
  public void testHotp3() {
    // Test use valid auth code after several invalid code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 5);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    // Attempt auth with invalid code
    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "296103");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });

    // Attempt auth with invalid code
    credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "571931");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });

    // Attempt auth with invalid code
    credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "881695");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });

    // Attempt auth with valid code
    credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "142559");
    }};
    authProvider.authenticate(credentials, onSuccess(user1 -> {
      long counter = user1.get("counter");
      assertEquals(6, counter);
      long authAttempt = user1.get("auth_attempts");
      assertEquals(4, authAttempt);
      testComplete();
    }));
  }

  @Test
  public void testHotp4() {
    // Test valid auth code without require auth

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "651075");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp5() {
    // Test valid auth code and repeated auth previous code

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "698956");
    }};
    authProvider.authenticate(credentials, onSuccess(user1 -> {
      long counter = user1.attributes().getInteger("counter");
      assertEquals(1, counter);
      Long authAttempt = user1.get("auth_attempt");
      assertNull(authAttempt);
    }));

    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp6() {
    // Test valid auth code after revoke hotp

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    authProvider.revokeHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "651075");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp7() {
    // test valid auth code for several users

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject user1Principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 7);
    }};
    UserImpl user1 = new UserImpl(user1Principal);
    authProvider.requestHotp(user1, onFailure(this::fail));

    JsonObject user2Principal = new JsonObject() {{
      put("identifier", "user2");
      put("key", USER2_KEY);
      put("counter", 3);
    }};
    UserImpl user2 = new UserImpl(user2Principal);
    authProvider.requestHotp(user2, onFailure(this::fail));

    JsonObject user1Credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "974712");
    }};
    authProvider.authenticate(user1Credentials, onSuccess(user -> {
      long counter = user.attributes().getLong("counter");
      assertEquals(8, counter);
      Long authAttempt = user.get("auth_attempt");
      assertNull(authAttempt);
    }));

    JsonObject user2Credentials = new JsonObject() {{
      put("identifier", "user2");
      put("code", "054804");
    }};
    authProvider.authenticate(user2Credentials, onSuccess(user -> {
      long counter = user.attributes().getLong("counter");
      assertEquals(4, counter);
      Long authAttempt = user.get("auth_attempt");
      assertNull(authAttempt);
    }));
  }

  @Test
  public void testHotp8() {
    // test valid authorization code for the first user

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject user1Principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 7);
    }};
    UserImpl user1 = new UserImpl(user1Principal);
    authProvider.requestHotp(user1, onFailure(this::fail));

    JsonObject user2Principal = new JsonObject() {{
      put("identifier", "user2");
      put("key", USER2_KEY);
      put("counter", 3);
    }};
    UserImpl user2 = new UserImpl(user2Principal);
    authProvider.requestHotp(user2, onFailure(this::fail));

    JsonObject user1Credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "974712");
    }};
    authProvider.authenticate(user1Credentials, onSuccess(user -> {
      long counter = user.attributes().getInteger("counter");
      assertEquals(8, counter);
      Integer authAttempt = user.get("auth_attempt");
      assertNull(authAttempt);
    }));

    JsonObject user2Credentials = new JsonObject() {{
      put("identifier", "user2");
      put("code", "302344");
    }};
    authProvider.authenticate(user2Credentials, onFailure(throwable -> testComplete()));
  }

  @Test
  public void testHotp9() {
    // Test valid auth code and unexpected password length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(8);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "698956");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp10() {
    // Test auth with unexpected code length

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setPasswordLength(6);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "29403113451");
    }};
    authProvider.authenticate(credentials, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp11() {
    // Test request code and auth attempts limit

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setAuthAttemptsLimit(5);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 6);
    }};
    final JsonObject attributes = new JsonObject() {{
      put("attempts_limit", 8);
    }};
    UserImpl user = new UserImpl(principal, attributes);

    authProvider.requestHotp(user, res -> {
      if (res.succeeded()) {
        fail();
      }
    });
  }

  @Test
  public void testHotp12() {
    // Test invalid auth code with attempts limit

    final int attemptsLimit = 3;
    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setAuthAttemptsLimit(attemptsLimit);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 0);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "738419");
    }};
    for (int i = 0; i < 10; i++) {
      int finalI = i;
      authProvider.authenticate(credentials, res -> {
        if (res.succeeded()) {
          fail();
        } else {
          if (finalI >= attemptsLimit) {
            assertNotNull(res.cause());
          }
        }
      });
    }
  }

  @Test
  public void testHotp13() {
    // Test valid auth code with using resynchronization

    HotpAuthOptions hotpAuthOptions = new HotpAuthOptions()
      .setLookAheadWindow(5);
    HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", USER1_KEY);
      put("counter", 8);
    }};
    UserImpl user = new UserImpl(principal);

    authProvider.requestHotp(user, onFailure(this::fail));

    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "203646");
    }};
    authProvider.authenticate(credentials, onSuccess(res -> {
      long counter = user.attributes().getLong("counter");
      assertEquals(11, counter);
      Long authAttempt = user.get("auth_attempt");
      assertNull(authAttempt);
    }));
  }
}
