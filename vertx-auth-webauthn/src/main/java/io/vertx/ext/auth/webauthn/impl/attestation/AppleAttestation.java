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
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.impl.AuthData;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static io.vertx.ext.auth.webauthn.impl.attestation.ASN1.*;
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
      "MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w" +
      "HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ" +
      "bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx" +
      "NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG" +
      "A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49" +
      "AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k" +
      "xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/" +
      "pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk" +
      "2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA" +
      "MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3" +
      "jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B" +
      "1bWeT0vT";

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
      ASN1.ASN extension = ASN1.parseASN1(appleExtension);
      if (extension.tag.type != OCTET_STRING) {
        throw new AttestationException("1.2.840.113635.100.8.2 Extension is not an ASN.1 OCTET string!");
      }
      // parse the octet as ASN.1 and expect it to se a sequence
      extension = parseASN1(extension.binary(0));
      if (extension.tag.type != SEQUENCE) {
        throw new AttestationException("1.2.840.113635.100.8.2 Extension is not an ASN.1 SEQUENCE!");
      }
      if (!MessageDigest.isEqual(nonce, extension.object(0).object(0).binary(0))) {
        throw new AttestationException("Certificate 1.2.840.113635.100.8.2 extension does not match nonce");
      }

      // 5. Verify credential public key matches the Subject Public Key of |credCert|.
      if (!credCert.getPublicKey().equals(authData.getCredentialJWK().getPublicKey())) {
        throw new AttestationException("credCert public key does not equal authData public key");
      }

      // meta data check
      metadata.verifyMetadata(
        authData.getAaguidString(),
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")),
        certChain);


    } catch (CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new AttestationException(e);
    }
  }
}
