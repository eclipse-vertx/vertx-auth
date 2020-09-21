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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Utilities to work with Json Web Encryption.
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
public final class JWE {

  public static byte[] encrypt(JWK key, byte[] payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    if (key.isFor(JWK.USE_ENC)) {
      final PublicKey publicKey = key.getPublicKey();
      if (publicKey == null) {
        throw new IllegalStateException("Key doesn't contain a pubKey material");
      }

      final Cipher cipher = Cipher.getInstance(key.getType());
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      cipher.update(payload);
      return cipher.doFinal();
    } else {
      throw new IllegalStateException("Key use is not 'enc'");
    }
  }

  public static byte[] decrypt(JWK key, byte[] payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    if (key.isFor(JWK.USE_ENC)) {
      final PrivateKey privateKey = key.getPrivateKey();
      if (privateKey == null) {
        throw new IllegalStateException("Key doesn't contain a privKey material");
      }

      final Cipher cipher = Cipher.getInstance(key.getType());
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      cipher.update(payload);
      return cipher.doFinal();
    } else {
      throw new IllegalStateException("Key use is not 'enc'");
    }
  }
}
