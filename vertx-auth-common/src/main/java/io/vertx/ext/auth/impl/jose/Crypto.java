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
package io.vertx.ext.auth.impl.jose;

/**
 * Internal common interface for all crypto algorithms.
 * This is just an utility in order to simplify sign and verify operations.
 *
 * @author Paulo Lopes
 */
public interface Crypto {

  /**
   * The key id or null.
   */
  default String getId() {
    return null;
  }

  /**
   * A not null label for the key, labels are the same for same algorithm, kid objects
   * but not necessarily different internal keys/certificates
   */
  String getLabel();

  byte[] sign(byte[] payload);

  boolean verify(byte[] signature, byte[] payload);
}

final class CryptoNone implements Crypto {
  private static final byte[] NOOP = new byte[0];

  @Override
  public String getLabel() {
    return "none";
  }

  @Override
  public byte[] sign(byte[] payload) {
    return NOOP;
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    return true;
  }
}
