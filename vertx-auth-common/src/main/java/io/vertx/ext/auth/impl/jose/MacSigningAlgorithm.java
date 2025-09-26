/*
 * Copyright 2025 Red Hat, Inc.
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
package io.vertx.ext.auth.impl.jose;

import javax.crypto.Mac;
import java.security.MessageDigest;

/**
 * @author Paulo Lopes
 */
class MacSigningAlgorithm implements SigningAlgorithm {

  private final String name;
  private final Mac mac;

  MacSigningAlgorithm(String name, Mac mac) {
    this.name = name;
    this.mac = mac;
  }

  @Override
  public boolean canSign() {
    return true;
  }

  @Override
  public boolean canVerify() {
    return true;
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public Signer signer() {
    return new Signer() {
      @Override
      public byte[] sign(byte[] data) {
        synchronized (MacSigningAlgorithm.this) {
          return mac.doFinal(data);
        }
      }

      @Override
      public synchronized boolean verify(byte[] expected, byte[] payload) {
        synchronized (MacSigningAlgorithm.this) {
          return MessageDigest.isEqual(expected, sign(payload));
        }
      }
    };
  }
}
