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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataException;

import java.security.*;
import java.security.cert.*;
import java.util.Collections;
import java.util.List;

import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.*;
import static io.vertx.ext.auth.webauthn.impl.ASN1.*;

/**
 * Implementation of the "android-key" attestation check.
 * <p>
 * Android KeyStore is a key management container, that defends key material from extraction.
 * Depending on the device, it can be either software or hardware backed.
 * <p>
 * For example if authenticator required to be FIPS/CC/PCI/FIDO compliant, then it needs
 * to be running on the device with FIPS/CC/PCI/FIDO compliant hardware, and it can be
 * found getting KeyStore attestation.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class AndroidKeyAttestation implements Attestation {

  private static final JsonArray EMPTY = new JsonArray(Collections.emptyList());

  @Override
  public String fmt() {
    return "android-key";
  }

  @Override
  public void validate(WebAuthnOptions options, MetaData metadata, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
    // Typical attestation object
    //{
    //    "fmt": "android-key",
    //    "authData": "base64",
    //    "attStmt": {
    //        "alg": -7,
    //        "sig": "base64",
    //        "x5c": [
    //            "base64",
    //            "base64",
    //            "base64"
    //        ]
    //    }
    //}

    try {
      byte[] clientDataHash = Attestation.hash("SHA-256", clientDataJSON);

      // Verifying attestation
      // 1. Concatenate authData with clientDataHash to create signatureBase
      byte[] signatureBase = Buffer.buffer()
        .appendBytes(authData.getRaw())
        .appendBytes(clientDataHash)
        .getBytes();
      // 2. Verify signature sig over the signatureBase using
      //    public key extracted from leaf certificate in x5c
      JsonObject attStmt = attestation.getJsonObject("attStmt");
      byte[] signature = attStmt.getBinary("sig");
      List<X509Certificate> certChain = parseX5c(attStmt.getJsonArray("x5c"));
      if (certChain.size() == 0) {
        throw new AttestationException("Invalid certificate chain");
      }

      final X509Certificate leafCert = certChain.get(0);

      // verify the signature
      verifySignature(
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")),
        leafCert,
        signature,
        signatureBase);

      // meta data check
      JsonObject statement = metadata.verifyMetadata(
        authData.getAaguidString(),
        PublicKeyCredential.valueOf(attStmt.getInteger("alg")),
        certChain);

      // Verifying attestation certificate
      // 1. Check that authData publicKey matches the public key in the attestation certificate
      JWK coseKey = authData.getCredentialJWK();
      if (!leafCert.getPublicKey().equals(coseKey.getPublicKey())) {
        throw new AttestationException("Certificate public key does not match public key in authData!");
      }
      // 2. Find Android KeyStore Extension with OID “1.3.6.1.4.1.11129.2.1.17” in certificate extensions.
      ASN attestationExtension = parseASN1(Buffer.buffer(leafCert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")));
      if (attestationExtension.tag.type != OCTET_STRING) {
        throw new AttestationException("Attestation Extension is not an ASN.1 OCTECT string!");
      }
      // parse the octec as ASN.1 and expect it to se a sequence
      attestationExtension = parseASN1(Buffer.buffer(attestationExtension.binary(0)));
      if (attestationExtension.tag.type != SEQUENCE) {
        throw new AttestationException("Attestation Extension Value is not an ASN.1 SEQUENCE!");
      }
      // get the data at index 4 (certificate challenge)
      byte[] data = attestationExtension.object(4).binary(0);

      // 3. Check that attestationChallenge is set to the clientDataHash.
      // verify that the client hash matches the certificate hash
      if (!MessageDigest.isEqual(clientDataHash, data)) {
        throw new AttestationException("Certificate attestation challenge is not set to the clientData hash!");
      }
      // 4. Check that both teeEnforced and softwareEnforced structures don’t contain allApplications(600) tag.
      // This is important as the key must strictly bound to the caller app identifier.
      ASN softwareEnforcedAuthz = attestationExtension.object(6);
      for (Object object : softwareEnforcedAuthz.value) {
        if (object instanceof ASN) {
          // verify if the that the list doesn't contain "allApplication" 600 flag
          if (((ASN) object).tag.number == 600) {
            throw new AttestationException("Software authorisation list contains 'allApplication' flag, which means that credential is not bound to the RP!");
          }
        }
      }
      // 4. Check that both teeEnforced and softwareEnforced structures don’t contain allApplications(600) tag.
      // This is important as the key must strictly bound to the caller app identifier.
      ASN teeEnforcedAuthz = attestationExtension.object(7);
      for (Object object : teeEnforcedAuthz.value) {
        if (object instanceof ASN) {
          // verify if the that the list doesn't contain "allApplication" 600 flag
          if (((ASN) object).tag.number == 600) {
            throw new AttestationException("TEE authorisation list contains 'allApplication' flag, which means that credential is not bound to the RP!");
          }
        }
      }

      if (statement == null || statement.getJsonArray("attestationRootCertificates", EMPTY).size() == 0) {
        // 5. Check that root certificate(last in the chain) is set to the root certificate
        // Google does not publish this certificate, so this was extracted from one of the attestations.
        final JsonArray x5c = attStmt.getJsonArray("x5c");
        if (!MessageDigest.isEqual(options.getRootCertificate(fmt()).getEncoded(), x5c.getBinary(x5c.size() - 1))) {
          throw new AttestationException("Root certificate is invalid!");
        }
      }

    } catch (MetaDataException | CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new AttestationException(e);
    }
  }
}
