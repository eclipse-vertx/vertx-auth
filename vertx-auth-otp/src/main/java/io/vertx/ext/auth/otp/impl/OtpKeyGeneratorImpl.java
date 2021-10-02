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

package io.vertx.ext.auth.otp.impl;

import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.OtpKeyGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static io.vertx.ext.auth.impl.Codec.base32Encode;

public class OtpKeyGeneratorImpl implements OtpKeyGenerator {

  public static final int DEFAULT_KEY_SIZE = 160;

  public static final String DEFAULT_HMAC_ALGORITHM = "HmacSHA1";

  private final KeyGenerator keyGenerator;

  public OtpKeyGeneratorImpl() {
    this(DEFAULT_HMAC_ALGORITHM);
  }

  public OtpKeyGeneratorImpl(String algorithm) {
    try {
      switch (algorithm) {
        case "HmacSHA1":
        case "HmacSHA256":
        case "HmacSHA512":
          keyGenerator = KeyGenerator.getInstance(algorithm);
          break;
        default:
          throw new IllegalArgumentException("Invalid algorithm, must be HmacSHA{1,256,512}");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public OtpKey generate() {
    return generate(DEFAULT_KEY_SIZE);
  }

  @Override
  public OtpKey generate(int keySize) {
    keyGenerator.init(keySize);
    SecretKey key = keyGenerator.generateKey();
    return new OtpKey()
      .setKey(base32Encode(key.getEncoded()))
      // strip the "Hmac" prefix
      .setAlgorithm(key.getAlgorithm().substring(4));
  }

  @Override
  public String getAlgorithm() {
    return keyGenerator.getAlgorithm();
  }
}
