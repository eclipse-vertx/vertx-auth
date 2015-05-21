/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.jwt.impl;

import javax.crypto.Mac;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * Internal common interface for all crypto algorithms.
 * This is just an utility in order to simplfy sign and verify operations.
 *
 * @author Paulo Lopes
 */
public interface Crypto {
  byte[] sign(byte[] payload);

  boolean verify(byte[] signature, byte[] payload);
}

/**
 * MAC based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoMac implements Crypto {
  private final Mac mac;

  CryptoMac(final Mac mac) {
    this.mac = mac;
  }

  @Override
  public byte[] sign(byte[] payload) {
    return mac.doFinal(payload);
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    return Arrays.equals(signature, mac.doFinal(payload));
  }
}


/**
 * Signature based Crypto implementation
 * @author Paulo Lopes
 */
final class CryptoSignature implements Crypto {
  private final Signature sig;

  CryptoSignature(final Signature signature) {
    this.sig = signature;
  }

  @Override
  public byte[] sign(byte[] payload) {
    try {
      sig.update(payload);
      return sig.sign();
    } catch (SignatureException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    try {
      sig.update(payload);
      return sig.verify(signature);
    } catch (SignatureException e) {
      throw new RuntimeException(e);
    }
  }
}

final class CryptoNone implements Crypto {
  private final byte[] NOOP = new byte[0];

  @Override
  public byte[] sign(byte[] payload) {
      return NOOP;
    }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
      return true;
    }
}
