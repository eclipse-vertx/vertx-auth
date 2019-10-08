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
import io.vertx.ext.jwt.JWK;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static io.vertx.ext.auth.webauthn.impl.attestation.ASN1.*;

public class AndroidKeyAttestation implements Attestation {

  // codecs
  private static final Base64.Decoder b64dec = Base64.getUrlDecoder();
  private static final Base64.Encoder b64enc = Base64.getUrlEncoder().withoutPadding();

  /* Android Keystore Root is not published anywhere.
   * This certificate was extracted from one of the attestations
   * The last certificate in x5c must match this certificate
   * This needs to be checked to ensure that malicious party wont generate fake attestations
   */
  private static final String ANDROID_KEYSTORE_ROOT = "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex-HA220Dpn7mthvsTWpdamguD_9_SQ59dx9EIm29sa_6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho--LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC_NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw";

  private final MessageDigest sha256;
  private final CertificateFactory x509;
  private final Signature sig;

  public AndroidKeyAttestation() {
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
    return "android-key";
  }

  @Override
  public void verify(JsonObject webAuthnResponse, byte[] clientDataJSON, JsonObject ctapMakeCredResp, AuthenticatorData authDataStruct) throws AttestationException {
    /*
    {
        "fmt": "android-key",
        "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bdd4450000000028f37d2b92b841c4b02a860cef7cc034004101552f0265f6e35bcc29877b64176690d59a61c3588684990898c544699139be88e32810515987ea4f4833071b646780438bf858c36984e46e7708dee61eedcbd0a50102032620012158203849a20fde26c34b0088391a5827783dff93880b1654088aadfaf57a259549a1225820743c4b5245cf2685cf91054367cd4fafb9484e70593651011fc0dcce7621c68f",
        "attStmt": {
            "alg": -7,
            "sig": "304402202ca7a8cfb6299c4a073e7e022c57082a46c657e9e53b28a6e454659ad024499602201f9cae7ff95a3f2372e0f952e9ef191e3b39ee2cedc46893a8eec6f75b1d9560",
            "x5c": [
                "308202ca30820270a003020102020101300a06082a8648ce3d040302308188310b30090603550406130255533113301106035504080c0a43616c69666f726e696131153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f6964313b303906035504030c32416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20496e7465726d656469617465301e170d3138313230323039313032355a170d3238313230323039313032355a301f311d301b06035504030c14416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d030107034200043849a20fde26c34b0088391a5827783dff93880b1654088aadfaf57a259549a1743c4b5245cf2685cf91054367cd4fafb9484e70593651011fc0dcce7621c68fa38201313082012d300b0603551d0f0404030207803081fc060a2b06010401d6790201110481ed3081ea0201020a01000201010a010104202a4382d7bbd89d8b5bdf1772cfecca14392487b9fd571f2eb72bdf97de06d4b60400308182bf831008020601676e2ee170bf831108020601b0ea8dad70bf831208020601b0ea8dad70bf853d08020601676e2edfe8bf85454e044c304a31243022041d636f6d2e676f6f676c652e6174746573746174696f6e6578616d706c65020101312204205ad05ec221c8f83a226127dec557500c3e574bc60125a9dc21cb0be4a00660953033a1053103020102a203020103a30402020100a5053103020104aa03020101bf837803020117bf83790302011ebf853e03020100301f0603551d230418301680143ffcacd61ab13a9e8120b8d5251cc565bb1e91a9300a06082a8648ce3d0403020348003045022067773908938055fd634ee413eaafc21d8ac7a9441bdf97af63914f9b3b00affe022100b9c0c89458c2528e2b25fa88c4d63ddc75e1bc80fb94dcc6228952d04f812418",
                "308202783082021ea00302010202021001300a06082a8648ce3d040302308198310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f69643133303106035504030c2a416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20526f6f74301e170d3136303131313030343630395a170d3236303130383030343630395a308188310b30090603550406130255533113301106035504080c0a43616c69666f726e696131153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f6964313b303906035504030c32416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20496e7465726d6564696174653059301306072a8648ce3d020106082a8648ce3d03010703420004eb9e79f8426359accb2a914c8986cc70ad90669382a9732613feaccbf821274c2174974a2afea5b94d7f66d4e065106635bc53b7a0a3a671583edb3e11ae1014a3663064301d0603551d0e041604143ffcacd61ab13a9e8120b8d5251cc565bb1e91a9301f0603551d23041830168014c8ade9774c45c3a3cf0d1610e479433a215a30cf30120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020284300a06082a8648ce3d040302034800304502204b8a9b7bee82bcc03387ae2fc08998b4ddc38dab272a459f690cc7c392d40f8e022100eeda015db6f432e9d4843b624c9404ef3a7cccbd5efb22bbe7feb9773f593ffb",
                "3082028b30820232a003020102020900a2059ed10e435b57300a06082a8648ce3d040302308198310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f69643133303106035504030c2a416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20526f6f74301e170d3136303131313030343335305a170d3336303130363030343335305a308198310b30090603550406130255533113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e205669657731153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f69643133303106035504030c2a416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20526f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004ee5d5ec7e1c0db6d03a67ee6b61bec4d6a5d6a682e0fff7f490e7d771f44226dbdb1affa16cbc7adc577d2569caab7b02d54015d3e432b2a8ed74eec487541a4a3633061301d0603551d0e04160414c8ade9774c45c3a3cf0d1610e479433a215a30cf301f0603551d23041830168014c8ade9774c45c3a3cf0d1610e479433a215a30cf300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020284300a06082a8648ce3d040302034700304402203521a3ef8b34461e9cd560f31d5889206adca36541f60d9ece8a198c6648607b02204d0bf351d9307c7d5bda35341da8471b63a585653cad4f24a7e74daf417df1bf"
            ]
        }
    }
    */

    try {
      byte[] clientDataHash = hash(clientDataJSON);

      byte[] signatureBase = Buffer.buffer()
        .appendBytes(authDataStruct.getRaw())
        .appendBytes(clientDataHash)
        .getBytes();

      JsonObject attStmt = ctapMakeCredResp.getJsonObject("attStmt");
      byte[] signature = b64dec.decode(attStmt.getString("sig"));

      JsonArray x5c = attStmt.getJsonArray("x5c");
      if (x5c == null || x5c.size() == 0) {
        throw new AttestationException("Invalid certificate chain");
      }

      final X509Certificate leafCert = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(b64dec.decode(x5c.getString(0))));
      // verify the leaf certificate
      leafCert.checkValidity();
      // verify the signature
      if (!verifySignature(signature, signatureBase, leafCert)) {
        throw new AttestationException("Failed to verify the signature!");
      }

      // STEP 31 Comment this line below if you allow rooted device for login
      if (!ANDROID_KEYSTORE_ROOT.equals(x5c.getString(x5c.size() - 1))) {
        throw new AttestationException("Root certificate is invalid!");
      }

      List<X509Certificate> certChain = new ArrayList<>();
      certChain.add(leafCert);
      for (int i = 1; i < x5c.size(); i++) {
        final X509Certificate c = (X509Certificate) x509.generateCertificate(new ByteArrayInputStream(b64dec.decode(x5c.getString(i))));
        // verify the leaf certificate
        c.checkValidity();
        certChain.add(c);
      }
      // validate the chain
      validateCertificatePath(certChain);

      // verify the key
      JWK coseKey = authDataStruct.getCredentialJWK();

      // the authenticator key must be the same as the leaf certificate
      if (!leafCert.getPublicKey().equals(coseKey.unwrap())) {
        throw new AttestationException("Certificate public key does not match public key in authData!");
      }

      // verify certificate requirements
      ASN attestationExtension = parseASN1(Buffer.buffer(leafCert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")));

      if (attestationExtension.tag.number != OCTET_STRING) {
        throw new AttestationException("Attestation Extension is not an ASN.1 OCTECT string!");
      }

      // parse the octec as ASN.1 and expect it to se a sequence
      attestationExtension = parseASN1(Buffer.buffer(attestationExtension.binary(0)));

      if (attestationExtension.tag.number != SEQUENCE) {
        throw new AttestationException("Attestation Extension Value is not an ASN.1 SEQUENCE!");
      }

      // get the data at index 4 (certificate challenge)
      byte[] data = attestationExtension.object(4).binary(0);

      // verify that the client hash matches the certificate hash
      if (!b64enc.encodeToString(clientDataHash).equals(b64enc.encodeToString(data))) {
        throw new AttestationException("Certificate attestation challenge is not set to the clientData hash!");
      }

      ASN softwareEnforcedAuthz = attestationExtension.object(6);

      for (Object object : softwareEnforcedAuthz.value) {
        if (object instanceof ASN) {
          // verify if the that the list doesn't contain "allApplication" 600 flag
          if (((ASN) object).tag.number == 600) {
            throw new AttestationException("Software authorisation list contains 'allApplication' flag, which means that credential is not bound to the RP!");
          }
        }
      }

      ASN teeEnforcedAuthz = attestationExtension.object(7);

      for (Object object : teeEnforcedAuthz.value) {
        if (object instanceof ASN) {
          // verify if the that the list doesn't contain "allApplication" 600 flag
          if (((ASN) object).tag.number == 600) {
            throw new AttestationException("TEE authorisation list contains 'allApplication' flag, which means that credential is not bound to the RP!");
          }
        }
      }
    } catch (CertificateException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
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
