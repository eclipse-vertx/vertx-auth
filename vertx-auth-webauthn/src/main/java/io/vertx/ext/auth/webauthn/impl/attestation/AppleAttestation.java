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

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.webauthn.impl.AuthData;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.*;

/**
 * Implementation of the Apple attestation check.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class AppleAttestation implements Attestation {

  /**
   * Apple WebAuthn Root CA PEM
   *
   * Downloaded from https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
   *
   * Valid until 03/14/2045 @ 5:00 PM PST
   */
  private static final String APPLE_WEBAUTHN_ROOT_CA =
    "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG" +
      "EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll" +
      "dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD" +
      "VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw" +
      "HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx" +
      "EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT" +
      "BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq" +
      "QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH" +
      "KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex-HA220Dpn7mthvsTWpdamguD_9_SQ59" +
      "dx9EIm29sa_6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O" +
      "BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W" +
      "EOR5QzohWjDPMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgKEMAoGCCqG" +
      "SM49BAMCA0cAMEQCIDUho--LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN" +
      "C_NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw";

  public AppleAttestation() {
  }

  @Override
  public String fmt() {
    return "apple";
  }

  @Override
  public void validate(Metadata metadata, JsonObject webauthn, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
    try {
      byte[] clientDataHash = hash("SHA-256", clientDataJSON);

      // Check attStmt and it contains “x5c” then its a FULL attestation.
      JsonObject attStmt = attestation.getJsonObject("attStmt");
      byte[] signature = attStmt.getBinary("sig");

      if (!attStmt.containsKey("x5c")) {
        throw new AttestationException("No attestation x5c");
      }

      List<X509Certificate> certChain = parseX5c(attStmt.getJsonArray("x5c"));

      if (certChain.size() == 0) {
        throw new AttestationException("no certificates in x5c field");
      }

      certChain.add(JWS.parseX5c(APPLE_WEBAUTHN_ROOT_CA));

      // 1. Verify |x5c| is a valid certificate chain starting from the |credCert| to the Apple WebAuthn root certificate.
      CertificateHelper.checkValidity(certChain, true);

      // 2. Concatenate |authenticatorData| and |clientDataHash| to form |nonceToHash|.
      byte[] nonceToHash = Buffer.buffer()
        .appendBytes(authData.getRaw())
        .appendBytes(clientDataHash)
        .getBytes();

      // 3. Perform SHA-256 hash of |nonceToHash| to produce |nonce|.
      byte[] nonce = Attestation.hash("SHA-256", nonceToHash);

      // 4. Verify |nonce| matches the value of the extension with OID ( 1.2.840.113635.100.8.2 ) in |credCert|.
      final X509Certificate credCert = certChain.get(0);
      byte[] appleExtension = credCert.getExtensionValue("1.2.840.113635.100.8.2");
      if (!MessageDigest.isEqual(nonce, appleExtension)) {
        throw new AttestationException("Certificate 1.2.840.113635.100.8.2 extension does not match nonce");
      }

      // 5. Verify credential public key matches the Subject Public Key of |credCert|.
      if (!credCert.getPublicKey().equals(authData.getCredentialJWK().getPublicKey())) {
        throw new AttestationException("credCert public key does not equal authData public key");
      }

    } catch (CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new AttestationException(e);
    }
  }
}
