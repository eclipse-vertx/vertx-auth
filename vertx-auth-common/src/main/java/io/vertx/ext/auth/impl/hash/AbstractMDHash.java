/*
 *  Copyright (c) 2011-2019 The original author or authors
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *       The Eclipse Public License is available at
 *       http://www.eclipse.org/legal/epl-v10.html
 *
 *       The Apache License v2.0 is available at
 *       http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Abstract implementation of hashing algorithms based on <code>java.security.MessageDigest</code>.
 *
 * @author <a href="mailto:lgao@redhat.com">Lin Gao</a>
 */
public abstract class AbstractMDHash implements HashingAlgorithm {

  private static final Base64.Encoder B64ENC = Base64.getEncoder();

  private final String alg;
  private final MessageDigest md;

  AbstractMDHash(final String algorithm) {
    try {
      alg = algorithm;
      md = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException(algorithm + " is not available", nsae);
    }
  }

  @Override
  public String algorithm() {
    return alg;
  }

  @Override
  public String hash(HashString hashString, String password) {
    return B64ENC.encodeToString(md.digest(password.getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public byte[] hash(byte[] rawValue) {
    return md.digest(rawValue);
  }
}
