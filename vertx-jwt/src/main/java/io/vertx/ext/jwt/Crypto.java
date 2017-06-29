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
package io.vertx.ext.jwt;

import io.vertx.ext.jwt.impl.SignatureHelper;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Mac;

/**
 * Internal common interface for all crypto algorithms.
 * This is just an utility in order to simplfy sign and verify operations.
 *
 * @author Paulo Lopes
 */
public interface Crypto {

  String[] ECDSA_ALGORITHMS = {
    "SHA256withECDSA",
    "SHA384withECDSA",
    "SHA512withECDSA"
  };

  byte[] sign(byte[] payload);

  boolean verify(byte[] signature, byte[] payload);

  default boolean isECDSA(String algorithm) {
    for (String alg : ECDSA_ALGORITHMS) {
      if (alg.equals(algorithm)) {
        return true;
      }
    }

    return false;
  }

  default int ECDSALength(String algorithm) {
    switch (algorithm) {
      case "SHA256withECDSA":
        return 64;
      case "SHA384withECDSA":
        return 96;
      case "SHA512withECDSA":
        return 132;
    }

    return -1;
  }
}

/**
 * MAC based Crypto implementation
 *
 * @author Paulo Lopes
 */
final class CryptoMac implements Crypto {
  private final Mac mac;

  CryptoMac(final Mac mac) {
    this.mac = mac;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    return mac.doFinal(payload);
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    return Arrays.equals(signature, sign(payload));
  }
}

/**
 * Public Key based Crypto implementation
 *
 * @author Paulo Lopes
 */
final class CryptoPublicKey implements Crypto {
  private final Signature sig;
  private final PublicKey publicKey;
  private final boolean ecdsa;

  CryptoPublicKey(final String algorithm, final PublicKey publicKey) {
    this.publicKey = publicKey;
    this.ecdsa = isECDSA(algorithm);

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // error
      throw new RuntimeException(e);
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    throw new RuntimeException("CryptoPublicKey cannot sign");
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    try {
      sig.initVerify(publicKey);
      sig.update(payload);
      if (ecdsa) {
        return sig.verify(SignatureHelper.toDER(signature));
      } else {
        return sig.verify(signature);
      }
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}

/**
 * Public Key based Crypto implementation
 *
 * @author Paulo Lopes
 */
final class CryptoPrivateKey implements Crypto {
  private final Signature sig;
  private final PrivateKey privateKey;
  private final boolean ecdsa;
  private final int ecdsaSignatureLength;

  CryptoPrivateKey(final String algorithm, final PrivateKey privateKey) {
    this.privateKey = privateKey;
    this.ecdsa = isECDSA(algorithm);
    this.ecdsaSignatureLength = ECDSALength(algorithm);

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // error
      throw new RuntimeException(e);
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    try {
      sig.initSign(privateKey);
      sig.update(payload);
      if (ecdsa) {
        return SignatureHelper.toJWS(sig.sign(), ecdsaSignatureLength);
      } else {
        return sig.sign();
      }
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    throw new RuntimeException("CryptoPrivateKey cannot verify");
  }
}

/**
 * Signature based Crypto implementation
 *
 * @author Paulo Lopes
 */
final class CryptoSignature implements Crypto {
  private final Signature sig;
  private final PrivateKey privateKey;
  private final X509Certificate certificate;
  private final boolean ecdsa;
  // the expected length of the ECDSA JWS signature.
  private final int ecdsaSignatureLength;

  CryptoSignature(final String algorithm, final X509Certificate certificate, final PrivateKey privateKey) {
    this.certificate = certificate;
    this.privateKey = privateKey;
    this.ecdsa = isECDSA(algorithm);
    this.ecdsaSignatureLength = ECDSALength(algorithm);

    Signature signature;
    try {
      // use default
      signature = Signature.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      // fallback
      try {
        signature = Signature.getInstance(certificate.getSigAlgName());
      } catch (NoSuchAlgorithmException e1) {
        // error
        throw new RuntimeException(e);
      }
    }

    this.sig = signature;
  }

  @Override
  public synchronized byte[] sign(byte[] payload) {
    try {
      sig.initSign(privateKey);
      sig.update(payload);
      if (ecdsa) {
        return SignatureHelper.toJWS(sig.sign(), ecdsaSignatureLength);
      } else {
        return sig.sign();
      }
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public synchronized boolean verify(byte[] signature, byte[] payload) {
    try {
      sig.initVerify(certificate);
      sig.update(payload);
      if (ecdsa) {
        return sig.verify(SignatureHelper.toDER(signature));
      } else {
        return sig.verify(signature);
      }
    } catch (SignatureException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }
}

final class CryptoNone implements Crypto {
  private static final byte[] NOOP = new byte[0];

  @Override
  public byte[] sign(byte[] payload) {
    return NOOP;
  }

  @Override
  public boolean verify(byte[] signature, byte[] payload) {
    return true;
  }
}
