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

import io.netty.util.concurrent.FastThreadLocal;
import io.netty.util.concurrent.FastThreadLocalThread;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * Utilities to work with Json Web Encryption. This is not fully implemented according to the RFC/spec.
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
public final class JWE {

  private static final FastThreadLocal<Cipher> CURRENT_CIPHER = new FastThreadLocal<>();

  private final JWK jwk;

  public JWE(JWK jwk) {
    if (jwk.use() == null || "enc".equals(jwk.use())) {
      throw new IllegalArgumentException("JWK isn't meant to perform JWE operations");
    }

    getCipher(jwk.kty()); //just validate if cipher is available
    this.jwk = jwk;
  }

  public byte[] encrypt(byte[] payload) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    final PublicKey publicKey = jwk.publicKey();
    if (publicKey == null) {
      throw new IllegalStateException("Key doesn't contain a pubKey material");
    }

    Cipher cipher = getCipher(jwk.kty());
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    cipher.update(payload);
    return cipher.doFinal();
  }

  public byte[] decrypt(byte[] payload) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    final PrivateKey privateKey = jwk.privateKey();
    if (privateKey == null) {
      throw new IllegalStateException("Key doesn't contain a secKey material");
    }

    Cipher cipher = getCipher(jwk.kty());
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    cipher.update(payload);
    return cipher.doFinal();
  }

  public String label() {
    return jwk.label();
  }

  private static Cipher getCipher(String algorithm) {
    Cipher cipher;
    if (Thread.currentThread() instanceof FastThreadLocalThread) {
      cipher = CURRENT_CIPHER.getIfExists();
      if (cipher == null) {
        cipher = getInstance(algorithm);
        CURRENT_CIPHER.set(cipher);
      }
    } else {
      cipher = getInstance(algorithm);
    }
    return cipher;
  }

  private static Cipher getInstance(String algorithm) {
    try {
      return Cipher.getInstance(algorithm);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new RuntimeException(e);
    }
  }
}
