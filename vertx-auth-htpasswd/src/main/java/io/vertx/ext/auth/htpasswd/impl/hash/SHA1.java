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
package io.vertx.ext.auth.htpasswd.impl.hash;

import io.vertx.ext.auth.HashString;
import io.vertx.ext.auth.HashingAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Implementation of the SHA1 Hashing algorithm
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class SHA1 implements HashingAlgorithm {

  private static final Base64.Encoder B64ENC = Base64.getEncoder();

  private final MessageDigest md;

  public SHA1() {
    try {
      md = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException("SHA1 is not available", nsae);
    }
  }

  @Override
  public String id() {
    return "{SHA}";
  }

  @Override
  public String hash(HashString hashString, String password) {
    return B64ENC.encodeToString(md.digest(password.getBytes(StandardCharsets.UTF_8)));
  }

  @Override
  public boolean needsSeparator() {
    return false;
  }
}
