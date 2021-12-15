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
import io.vertx.ext.auth.impl.CertificateHelper;
import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.webauthn.AttestationCertificates;
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.WebAuthnOptions;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaData;
import io.vertx.ext.auth.webauthn.impl.metadata.MetaDataException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static io.vertx.ext.auth.impl.Codec.base64Decode;
import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;
import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.hash;
import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.verifySignature;
import static io.vertx.ext.auth.webauthn.impl.metadata.MetaData.ATTESTATION_ANONCA;
import static io.vertx.ext.auth.webauthn.impl.metadata.MetaData.statementAttestationTypesContains;

/**
 * Implementation of the "android-safetynet" attestation check.
 * <p>
 * SafetyNet is a set of Google Play Services API’s, that are helpful for defence against security threats on Android,
 * such as device tampering, bad URLs, malicious apps, and fake user accounts. Main solutions that SafetyNet provides
 * are device attestation, safe browsing, re-captcha and app check APIs.
 *
 * @author <a href="mailto:pmlopes@gmail.com>Paulo Lopes</a>
 */
public class AndroidSafetynetAttestation implements Attestation {

  @Override
  public String fmt() {
    return "android-safetynet";
  }

  @Override
  public AttestationCertificates validate(WebAuthnOptions options, MetaData metadata, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
    // attestation format:
    //{
    //    "fmt": "android-safetynet",
    //    "authData": "base64",
    //    "attStmt": {
    //        "ver": "string",
    //        "response": "base64"
    //    }
    //}
    try {
      JsonObject attStmt = attestation.getJsonObject("attStmt");
      // for compliance ver is required to be a String
      if (!attStmt.containsKey("ver") || attStmt.getString("ver") == null || attStmt.getString("ver").length() == 0) {
        throw new AttestationException("Missing {ver} in attStmt");
      }
      // response is a JWT
      JsonObject token = JWT.parse(base64UrlDecode(attStmt.getString("response")));

      // verify the payload:
      // 1. Hash clientDataJSON using SHA256, to create clientDataHash
      byte[] clientDataHash = hash("SHA-256", clientDataJSON);
      // 2. Concatenate authData with clientDataHash to create nonceBase
      Buffer nonceBase = Buffer.buffer()
        .appendBytes(authData.getRaw())
        .appendBytes(clientDataHash);
      // 3. Hash nonceBase using SHA256 to create nonceBuffer.
      // 4. Check that “nonce” is set to expectedNonce
      if (!MessageDigest.isEqual(hash("SHA-256", nonceBase.getBytes()), base64Decode(token.getJsonObject("payload").getString("nonce")))) {
        throw new AttestationException("JWS nonce does not contains expected nonce!");
      }
      // 5. Check that “ctsProfileMatch” is set to true. If its not set to true, that means that device has been rooted
      // and so can not be trusted to provide trustworthy attestation.
      if (!token.getJsonObject("payload").getBoolean("ctsProfileMatch")) {
        throw new AttestationException("JWS ctsProfileMatch is false!");
      }
      // 6. Verify the timestamp
      long timestampMs = token.getJsonObject("payload").getLong("timestampMs", 0L);
      long now = System.currentTimeMillis();
      if (timestampMs > now || (timestampMs + options.getTimeout()) < now) {
        throw new AttestationException("timestampMs is invalid!");
      }

      // Verify the header
      JsonArray x5c = token.getJsonObject("header").getJsonArray("x5c");
      if (x5c == null || x5c.size() == 0) {
        throw new AttestationException("Invalid certificate chain");
      }

      List<X509Certificate> certChain = new ArrayList<>();

      for (int i = 0; i < x5c.size(); i++) {
        final byte[] bytes = base64Decode(x5c.getString(i));
        certChain.add(JWS.parseX5c(bytes));
        // patch the x5c data to be base64url
        x5c.set(i, bytes);
      }

      // 1. Get leaf certificate of x5c certificate chain, decode it,
      // and check that it was issued for “attest.android.com”
      if (!"attest.android.com".equals(CertificateHelper.getCertInfo(certChain.get(0)).subject("CN"))) {
        throw new AttestationException("The common name is not set to 'attest.android.com'!");
      }

      // If available, validate attestation alg and x5c with info in the metadata statement
      JsonObject statement = metadata.verifyMetadata(
        authData.getAaguidString(),
        PublicKeyCredential.valueOf(token.getJsonObject("header").getString("alg")),
        certChain,
        // Attach the root certificate to the end of header.x5c and try to verify it
        options.getRootCertificate(fmt())
      );

      if (statement != null) {
        // verify that the statement allows this type of attestation
        if (!statementAttestationTypesContains(statement, ATTESTATION_ANONCA)) {
          throw new AttestationException("Metadata does not indicate support for anonca attestations");
        }
      }

      // Verify the signature
      verifySignature(
        PublicKeyCredential.valueOf(token.getJsonObject("header").getString("alg")),
        certChain.get(0),
        base64UrlDecode(token.getString("signature")),
        token.getString("signatureBase").getBytes(StandardCharsets.UTF_8));

      return new AttestationCertificates()
        .setAlg(PublicKeyCredential.valueOf(token.getJsonObject("header").getString("alg")))
        .setX5c(x5c);

    } catch (MetaDataException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new AttestationException(e);
    }
  }
}
