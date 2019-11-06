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

import com.fasterxml.jackson.core.JsonParser;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;
import io.vertx.ext.auth.webauthn.impl.CBOR;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import static io.vertx.ext.auth.webauthn.impl.AuthenticatorData.USER_PRESENT;

public class FidoU2fAttestation implements Attestation {

  // codecs
  private static final Base64.Decoder b64dec = Base64.getUrlDecoder();

  private final MessageDigest sha256;
  private final CertificateFactory x509;
  private final Signature sig;

  public FidoU2fAttestation() {
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
      x509 = CertificateFactory.getInstance("X.509");
      sig = Signature.getInstance("SHA256withECDSA");
    } catch (NoSuchAlgorithmException | CertificateException e) {
      throw new AttestationException(e);
    }
  }

  @Override
  public String fmt() {
    return "fido-u2f";
  }

  @Override
  public void verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authr) {
    try {
      if (!authr.is(USER_PRESENT)) {
        throw new AttestationException("User was NOT present during authentication!");
      }

      byte[] clientDataHash = hash(clientDataJSON);

      byte[] publicKey = COSEECDHAtoPKCS(authr.getCredentialPublicKey());
      Buffer signatureBase = Buffer.buffer()
        .appendByte((byte) 0x00) // reserved byte
        .appendBytes(authr.getRpIdHash())
        .appendBytes(clientDataHash)
        .appendBytes(authr.getCredentialId())
        .appendBytes(publicKey);

      JsonObject attStmt = ctapMakeCredResp.getJsonObject("attStmt");
      JsonArray x5c = attStmt.getJsonArray("x5c");

      final X509Certificate x509Certificate = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(b64dec.decode(x5c.getString(0))));
      // check the certificate
      x509Certificate.checkValidity();
      // certificate valid lets verify signatures
      byte[] signature = b64dec.decode(attStmt.getString("sig"));

      if (!verifySignature(signature, signatureBase.getBytes(), x509Certificate)) {
        throw new AttestationException("Failed to verify signature");
      }
    } catch (CertificateException | IOException | InvalidKeyException | SignatureException e) {
      throw new AttestationException(e);
    }
  }

  /**
   * Returns SHA-256 digest of the given data.
   *
   * @param data - data to hash
   * @return the hash
   */
  private byte[] hash(byte[] data) {
    synchronized (sha256) {
      sha256.update(data);
      return sha256.digest();
    }
  }

  private boolean verifySignature(byte[] signature, byte[] data, X509Certificate certificate) throws InvalidKeyException, SignatureException {
      synchronized (sig) {
        sig.initVerify(certificate);
        sig.update(data);
        return sig.verify(signature);
      }
  }

  /**
   * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
   *
   * @param cosePublicKey - COSE encoded public key
   * @return - RAW PKCS encoded public key
   */
  private static byte[] COSEECDHAtoPKCS(byte[] cosePublicKey) throws IOException {
      /*
         +------+-------+-------+---------+----------------------------------+
         | name | key   | label | type    | description                      |
         |      | type  |       |         |                                  |
         +------+-------+-------+---------+----------------------------------+
         | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
         |      |       |       | tstr    | the COSE Curves registry         |
         |      |       |       |         |                                  |
         | x    | 2     | -2    | bstr    | X Coordinate                     |
         |      |       |       |         |                                  |
         | y    | 2     | -3    | bstr /  | Y Coordinate                     |
         |      |       |       | bool    |                                  |
         |      |       |       |         |                                  |
         | d    | 2     | -4    | bstr    | Private key                      |
         +------+-------+-------+---------+----------------------------------+
      */
      try (JsonParser parser = CBOR.cborParser(cosePublicKey)) {
        Map key = CBOR.parse(parser);

        return Buffer.buffer()
          .appendByte((byte) 0x04)
          .appendBytes(b64dec.decode((String) key.get("-2")))
          .appendBytes(b64dec.decode((String) key.get("-3")))
          .getBytes();
      }
  }
}
