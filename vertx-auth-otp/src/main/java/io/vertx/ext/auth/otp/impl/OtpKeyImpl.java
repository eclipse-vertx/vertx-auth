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

import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.otp.OtpKey;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class OtpKeyImpl implements OtpKey, SecretKey {

  private final Key key;

  private final String base32Encoded;

  public OtpKeyImpl(Buffer buffer, String algorithm) {
    this(buffer.getBytes(), algorithm);
  }

  public OtpKeyImpl(byte[] key, String algorithm) {
    this(new SecretKeySpec(key, algorithm));
  }

  public OtpKeyImpl(Key key) {
    this.key = key;
    base32Encoded = new Base32(false).encodeToString(key.getEncoded());
  }

  @Override
  public String getAlgorithm() {
    return key.getAlgorithm();
  }

  @Override
  public String getFormat() {
    return key.getFormat();
  }

  @Override
  public byte[] getEncoded() {
    return key.getEncoded();
  }

  @Override
  public Buffer getBuffer() {
    return Buffer.buffer(key.getEncoded());
  }

  @Override
  public String getBase32() {
    return base32Encoded;
  }
}
