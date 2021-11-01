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
import io.vertx.ext.auth.webauthn.AttestationCertificates;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.impl.asn.ASN1;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataException;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static io.vertx.ext.auth.impl.asn.ASN1.*;
import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.*;
import static io.vertx.ext.auth.webauthn.impl.metadata.MetaData.ATTESTATION_ANONCA;
import static io.vertx.ext.auth.webauthn.impl.metadata.MetaData.statementAttestationTypesContains;

/**
 * Implementation of the Apple attestation check.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class AppleAttestation implements Attestation {

  @Override
  public String fmt() {
    return "apple";
  }

  @Override
  public AttestationCertificates validate(WebAuthnOptions options, MetaData metadata, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
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

      certChain.add(options.getRootCertificate(fmt()));

      // 1. Verify |x5c| is a valid certificate chain starting from the |credCert| to the Apple WebAuthn root certificate.
      CertificateHelper.checkValidity(certChain, true, options.getRootCrls());

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
      if (!extension.is(OCTET_STRING)) {
        throw new AttestationException("1.2.840.113635.100.8.2 Extension is not an ASN.1 OCTET string!");
      }
      // parse the octet as ASN.1 and expect it to se a sequence
      extension = parseASN1(extension.binary(0));
      if (!extension.is(SEQUENCE)) {
        throw new AttestationException("1.2.840.113635.100.8.2 Extension is not an ASN.1 SEQUENCE!");
      }
      if (!MessageDigest.isEqual(nonce, extension.object(0).object(0).binary(0))) {
        throw new AttestationException("Certificate 1.2.840.113635.100.8.2 extension does not match nonce");
      }

      // 5. Verify credential public key matches the Subject Public Key of |credCert|.
      if (!credCert.getPublicKey().equals(authData.getCredentialJWK().publicKey())) {
        throw new AttestationException("credCert public key does not equal authData public key");
      }

      // https://w3c.github.io/webauthn/#sctn-apple-anonymous-attestation
      // the spec doesn't list "alg" yet devices do send it in some cases.
      // the "alg" is important to support metadata in the future if a device gets compromised.
      final PublicKeyCredential alg = attStmt.containsKey("alg") ?
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")) :
        null;

      // meta data check
      JsonObject statement = metadata.verifyMetadata(
        authData.getAaguidString(),
        alg,
        certChain);

      if (statement != null) {
        // verify that the statement allows this type of attestation
        if (!statementAttestationTypesContains(statement, ATTESTATION_ANONCA)) {
          throw new AttestationException("Metadata does not indicate support for anonca attestations");
        }
      }

      return new AttestationCertificates()
        .setAlg(alg)
        .setX5c(attStmt.getJsonArray("x5c"));

    } catch (MetaDataException | CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new AttestationException(e);
    }
  }
}
