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
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;
import io.vertx.ext.jwt.JWT;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class AndroidSafetynetAttestation implements Attestation {

  // codecs
  private static final Base64.Decoder ub64dec = Base64.getUrlDecoder();
  private static final Base64.Decoder b64dec = Base64.getDecoder();

  private static final String ANDROID_SAFETYNET_ROOT = "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==";

  private final MessageDigest sha256;
  private final CertificateFactory x509;
  private final Signature sig;

  public AndroidSafetynetAttestation() {
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
      x509 = CertificateFactory.getInstance("X.509");
      sig = Signature.getInstance("SHA256withRSA");
    } catch (NoSuchAlgorithmException | CertificateException e) {
      throw new AttestationException(e);
    }
  }

  @Override
  public String fmt() {
    return "android-safetynet";
  }

  @Override
  public void verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authr) throws AttestationException {

    try {
      JsonObject attStmt = ctapMakeCredResp.getJsonObject("attStmt");

      JsonObject token = JWT.parse(ub64dec.decode(attStmt.getString("response")));

      /* ----- Verify payload ----- */
      byte[] clientDataHashBuf = hash(clientDataJSON);

      Buffer nonceBase = Buffer.buffer()
        .appendBytes(authr.getRaw())
        .appendBytes(clientDataHashBuf);

      if (!MessageDigest.isEqual(hash(nonceBase.getBytes()), b64dec.decode(token.getJsonObject("payload").getString("nonce")))) {
        throw new AttestationException("JWS nonce does not contains expected nonce!");
      }

      if (!token.getJsonObject("payload").getBoolean("ctsProfileMatch")) {
        throw new AttestationException("JWS ctsProfileMatch is false!");
      }
      /* ----- Verify payload ENDS ----- */

      /* ----- Verify header ----- */
      JsonArray x5c = token.getJsonObject("header").getJsonArray("x5c");

      if (x5c == null || x5c.size() == 0) {
        throw new AttestationException("Invalid certificate chain");
      }

      // push the root certificate
      x5c.add(ANDROID_SAFETYNET_ROOT);

      List<X509Certificate> certChain = new ArrayList<>();

      for (int i = 0; i < x5c.size(); i++) {
        final X509Certificate c = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(b64dec.decode(x5c.getString(i))));
        // verify the certificate chain
        c.checkValidity();
        certChain.add(c);
      }
//
      X500Principal google = new X500Principal("CN=attest.android.com, O=Google LLC, L=Mountain View, ST=California, C=US");

      if (!google.equals(certChain.get(0).getSubjectX500Principal())) {
        throw new AttestationException("The common name is not set to 'attest.android.com'!");
      }

      validateCertificatePath(certChain);
      /* ----- Verify header ENDS ----- */

      /* ----- Verify signature ----- */
      if (!verifySignature(ub64dec.decode(token.getString("signature")), token.getString("signatureBase").getBytes(), certChain.get(0))) {
        throw new AttestationException("Failed to verify the signature!");
      }
      /* ----- Verify signature ENDS ----- */

    } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
      throw new AttestationException(e);
    }
  }

  private void validateCertificatePath(List<X509Certificate> certificates) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

    for (int i = 0; i < certificates.size(); i++) {
      X509Certificate subjectCert = certificates.get(i);
      X509Certificate issuerCert;

      if (i + 1 >= certificates.size()) {
        issuerCert = subjectCert;
      } else {
        issuerCert = certificates.get(i + 1);
      }

      // verify that the issuer matches the next one in the list
      if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
        throw new CertificateException("Failed to validate certificate path! Issuers dont match!");
      }

      // verify the certificate against the issuer
      subjectCert.verify(issuerCert.getPublicKey());
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
}
