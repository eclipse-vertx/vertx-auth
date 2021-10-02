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

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import java.util.Locale;

import static io.vertx.ext.auth.impl.Codec.base32Decode;

/**
 * Key of specific user.
 *
 * @author Dmitry Novikov
 */
@DataObject
public class OtpKey {

  private String key;
  private String algorithm;

  public OtpKey() {}

  public OtpKey(OtpKey other) {
    this.key = other.key;
    this.algorithm = other.algorithm;
  }

  public OtpKey(JsonObject json) {
    setKey(json.getString("key"));
    setAlgorithm(json.getString("algorithm"));
  }

  public String getKey() {
    return key;
  }

  public byte[] getKeyBytes() {
    return base32Decode(key);
  }

  public OtpKey setKey(String key) {
    this.key = key;
    return this;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public OtpKey setAlgorithm(String algorithm) {
    if (algorithm == null) {
      algorithm = "SHA1";
    } else {
      algorithm = algorithm.toUpperCase(Locale.US);
    }

    switch (algorithm) {
      case "SHA1":
      case "SHA256":
      case "SHA512":
        this.algorithm = algorithm;
        return this;
      default:
        throw new IllegalArgumentException("Invalid algorithm, must be SHA{1,256,512}");
    }
  }

  public JsonObject toJson() {
    return new JsonObject()
      .put("key", getKey())
      .put("algorithm", getAlgorithm());
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
