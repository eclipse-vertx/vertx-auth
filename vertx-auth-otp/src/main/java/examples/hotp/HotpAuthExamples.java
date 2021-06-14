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
import io.vertx.ext.auth.otp.utils.AuthenticatorUriGenerator;
import io.vertx.ext.auth.otp.utils.OtpKey;
import io.vertx.ext.auth.otp.utils.OtpKeyGenerator;
import net.glxn.qrgen.core.image.ImageType;
import net.glxn.qrgen.javase.QRCode;
import org.apache.commons.codec.binary.Base32;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;

public class HotpAuthExamples {

  public static void example1() {
    // generate key
    OtpKeyGenerator keyGenerator = new OtpKeyGenerator();
    OtpKey otpKey = keyGenerator.generate();

    // create qr code
    URI uri = AuthenticatorUriGenerator.generateHotpUri(otpKey, "vertx_hotp", "user_1", "service_1");
    QRCode qrCode = QRCode.from(uri.toString()).to(ImageType.PNG).withSize(512, 512);

    try(FileOutputStream fos = new FileOutputStream("otp_key.png")) {
      qrCode.writeTo(fos);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public static void example2() {
    final HotpAuthOptions hotpAuthOptions = new HotpAuthOptions();
    final HotpAuth authProvider = HotpAuth.create(hotpAuthOptions);

    // key
    final String userKey = "2P3V27SMNQHEE4CYK26ZHTN5HPIGWT4R";
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
      put("code", "651075");
    }};
    authProvider.authenticate(credentials);
  }
}
