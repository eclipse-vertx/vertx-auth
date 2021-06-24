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

package examples.hotp;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.OtpKeyGenerator;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;

public class HotpAuthExamples {

  public static void example1() {
    // generate new key
    OtpKeyGenerator keyGenerator = OtpKeyGenerator.create();
    OtpKey otpKey = keyGenerator.generate();
  }

  public static void example2() {
    final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    final HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    // key
    final String userKey = "OK7JVNHJO5ZMC57QLYJ6QNTOZFKVN76Y";
    final OtpKey otpKey = new OtpKey()
      .setKey(userKey)
      .setAlgorithm("HmacSHA1");

    // request hotp for user
    JsonObject principal = new JsonObject()
      .put("identifier", "user1")
      .put("key", otpKey.getKey())
      .put("counter", 0);

    authProvider.requestHotp(User.create(principal), userAsyncResult -> {});

    // auth user hotp
    JsonObject credentials = new JsonObject()
      .put("identifier", "user1")
      .put("code", "249916");

    authProvider.authenticate(credentials);
  }
}
