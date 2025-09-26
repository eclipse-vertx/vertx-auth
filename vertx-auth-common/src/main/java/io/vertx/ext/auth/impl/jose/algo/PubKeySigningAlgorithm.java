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
package io.vertx.ext.auth.impl.jose.algo;

import io.vertx.ext.auth.impl.jose.JWS;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

import static io.vertx.ext.auth.impl.jose.JWS.getSignatureLength;

/**
 * @author Paulo Lopes
 */
public class PubKeySigningAlgorithm extends SigningAlgorithm {

  public static PubKeySigningAlgorithm createPubKeySigningAlgorithm(String alg, PrivateKey privateKey, PublicKey publicKey, String id) {
    return new PubKeySigningAlgorithm(alg, privateKey, publicKey, id);
  }

  public static PubKeySigningAlgorithm createPubKeySigningAlgorithm(String alg, PrivateKey privateKey, PublicKey publicKey) {
    return new PubKeySigningAlgorithm(alg, privateKey, publicKey, null);
  }

  public static PubKeySigningAlgorithm createPubKeySigningAlgorithm(String alg, PublicKey publicKey) {
    return new PubKeySigningAlgorithm(alg, null, publicKey, null);
  }

  public static PubKeySigningAlgorithm createPubKeySigningAlgorithm(String alg, PrivateKey privateKey) {
    return new PubKeySigningAlgorithm(alg, privateKey, null, null);
  }

  private final String alg;
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final String id;

  private PubKeySigningAlgorithm(String alg, PrivateKey privateKey, PublicKey publicKey, String id) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.alg = Objects.requireNonNull(alg);
    this.id = id;
  }

  public PrivateKey privateKey() {
    return privateKey;
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  @Override
  public String id() {
    return id;
  }

  @Override
  public boolean canSign() {
    return privateKey != null;
  }

  @Override
  public boolean canVerify() {
    return publicKey != null;
  }

  @Override
  public String name() {
    return alg;
  }

  @Override
  public Signer signer() throws GeneralSecurityException {
    Signature signature = Signer.getSignature(alg);
    // the length of the signature. This is derived from the algorithm name
    // this will help to cope with signatures that are longer (yet valid) than
    // the expected result
    int len = getSignatureLength(alg, publicKey);
    return new Signer() {
      @Override
      public synchronized byte[] sign(byte[] data) throws GeneralSecurityException {
        if (privateKey == null) {
          throw new IllegalStateException("JWK doesn't contain secKey material");
        }
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
      }

      @Override
      public synchronized boolean verify(byte[] expected, byte[] payload) throws GeneralSecurityException {
        if (publicKey == null) {
          throw new IllegalStateException("JWK doesn't contain pubKey material");
        }
        signature.initVerify(publicKey);
        signature.update(payload);
        if (expected.length < len) {
          // need to adapt the expectation to make the RSA? engine happy
          byte[] normalized = new byte[len];
          System.arraycopy(expected, 0, normalized, 0, expected.length);
          return signature.verify(normalized);
        } else {
          return signature.verify(expected);
        }
      }
    };
  }
}
