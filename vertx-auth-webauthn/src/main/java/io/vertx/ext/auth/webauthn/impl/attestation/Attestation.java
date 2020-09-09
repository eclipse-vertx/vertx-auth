/*
 * Copyright 2019 Red Hat, Inc.
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

package io.vertx.ext.auth.webauthn.impl.attestation;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AuthData;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public interface Attestation {

  /**
   * The unique identifier for the attestation
   * @return String
   */
  String fmt();

  /**
   * The implementation of the Attestation verification.
   *
   * @param webauthn the JSON request received from the client
   * @param clientDataJSON the binary client data json
   * @param attestation the JSON representation of the attestation
   * @param authData the authenticator data
   *
   * @throws AttestationException if the validation fails
   */
  void validate(JsonObject webauthn, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException;

  /**
   * Returns SHA-256 digest of the given data.
   *
   * @param data - data to hash
   * @return the hash
   */
  static byte[] hash(final String algorithm, byte[] data) throws NoSuchAlgorithmException {
    if (algorithm == null) {
      throw new NullPointerException("algorithm is null");
    }

    final MessageDigest md = MessageDigest.getInstance(algorithm);

    md.update(data);
    return md.digest();
  }

  /**
   * Verify if the data provider matches the signature based of the given certificate.
   *
   * @param certificate - origin certificate
   * @param signature   - received signature
   * @param data        - data to verify
   */
  static void verifySignature(Signature sig, X509Certificate certificate, byte[] signature, byte[] data) throws InvalidKeyException, SignatureException {
    sig.initVerify(certificate);
    sig.update(data);

    if (!sig.verify(signature)) {
      throw new AttestationException("Failed to verify signature");
    }
  }

  /**
   * Parses a JsonArray of certificates to a X509Certificate list
   * @param factory the factory that will parse the certificate base64 data
   * @param x5c the json array
   * @return list of X509Certificates

   * @throws CertificateException
   */
  static List<X509Certificate> parseX5c(CertificateFactory factory, JsonArray x5c) throws CertificateException {
    List<X509Certificate> certChain = new ArrayList<>();

    if (x5c == null || x5c.size() == 0) {
      return certChain;
    }

    for (int i = 0; i < x5c.size(); i++) {
      certChain.add(parseX5c(factory, x5c.getBinary(i)));
    }

    return certChain;
  }

  /**
   * Parses a JsonArray of certificates to a X509Certificate list
   * @param factory the factory that will parse the certificate base64 data
   * @param base64 the base64 string
   * @return list of X509Certificates

   * @throws CertificateException
   */
  static X509Certificate parseX5c(CertificateFactory factory, byte[] base64) throws CertificateException {
    return (X509Certificate) factory
          .generateCertificate(new ByteArrayInputStream(base64));
  }
}
