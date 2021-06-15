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
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;
import io.vertx.ext.auth.otp.utils.OtpKey;
import io.vertx.ext.auth.otp.utils.OtpKeyGenerator;
import org.apache.commons.codec.binary.Base32;

public class HotpAuthExamples {

  public static void example1() {
    // generate new key
    OtpKeyGenerator keyGenerator = new OtpKeyGenerator();
    OtpKey otpKey = keyGenerator.generate();
  }

  public static void example2() {
    final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    final HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    // key
    final String userKey = "OK7JVNHJO5ZMC57QLYJ6QNTOZFKVN76Y";
    final byte[] keyBytes = new Base32(false).decode(userKey);
    final OtpKey otpKey = new OtpKey(keyBytes, "HmacSHA1");

    // request hotp for user
    JsonObject principal = new JsonObject() {{
      put("identifier", "user1");
      put("key", otpKey.getBase32());
      put("counter", 0);
    }};
    authProvider.requestHotp(new UserImpl(principal), userAsyncResult -> {});

    // auth user hotp
    JsonObject credentials = new JsonObject() {{
      put("identifier", "user1");
      put("code", "249916");
    }};
    authProvider.authenticate(credentials);
  }
}
