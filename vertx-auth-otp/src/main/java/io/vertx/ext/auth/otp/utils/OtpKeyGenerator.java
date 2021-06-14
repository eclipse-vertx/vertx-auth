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

package io.vertx.ext.auth.otp.utils;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

public class OtpKeyGenerator {

  public static final int DEFAULT_KEY_SIZE = 160;

  public static final String DEFAULT_HMAC_ALGORITHM = "HmacSHA1";

  private final KeyGenerator keyGenerator;

  public OtpKeyGenerator() {
    this(DEFAULT_HMAC_ALGORITHM);
  }

  public OtpKeyGenerator(String algorithm) {
    try {
      keyGenerator = KeyGenerator.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public OtpKey generate() {
    return generate(DEFAULT_KEY_SIZE);
  }

  public OtpKey generate(int keySize) {
    keyGenerator.init(keySize);
    return new OtpKey(keyGenerator.generateKey());
  }

  public String getAlgorithm() {
    return keyGenerator.getAlgorithm();
  }
}
