/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

/**
 * Implementation of the PBKDF2 Hashing algorithm
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class PBKDF2 implements HashingAlgorithm {

  private static final int DEFAULT_ITERATIONS = 10000;
  private static final Base64.Decoder B64DEC = Base64.getDecoder();
  private static final Base64.Encoder B64ENC = Base64.getEncoder();

  private static final Set<String> DEFAULT_CONFIG = Collections.singleton("it");

  private final SecretKeyFactory skf;

  public PBKDF2() {
    try {
      skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("PBKDF2 is not available", nsae);
    }
  }

  @Override
  public String id() {
    return "pbkdf2";
  }

  @Override
  public Set<String> params() {
    return DEFAULT_CONFIG;
  }

  @Override
  public String hash(HashString hashString, String password) {

    int iterations;

    try {
      if (hashString.params() != null) {
        iterations = Integer.getInteger(hashString.params().get("it"));
      } else {
        iterations = DEFAULT_ITERATIONS;
      }
    } catch (RuntimeException e) {
      iterations = DEFAULT_ITERATIONS;
    }

    if (hashString.salt() == null) {
      throw new RuntimeException("hashString salt is null");
    }

    byte[] salt = B64DEC.decode(hashString.salt());

    PBEKeySpec spec = new PBEKeySpec(
      password.toCharArray(),
      salt,
      iterations,
      64 * 8);

    try {
      return B64ENC.encodeToString(skf.generateSecret(spec).getEncoded());
    } catch (InvalidKeySpecException ikse) {
      throw new RuntimeException(ikse);
    }
  }
}
