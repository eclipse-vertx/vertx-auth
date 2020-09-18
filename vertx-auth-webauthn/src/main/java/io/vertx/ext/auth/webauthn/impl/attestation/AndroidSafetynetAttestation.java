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
import io.vertx.ext.auth.webauthn.PublicKeyCredential;
import io.vertx.ext.auth.webauthn.impl.AuthData;
import io.vertx.ext.auth.impl.jose.JWT;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static io.vertx.ext.auth.webauthn.impl.attestation.Attestation.*;

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

  // codecs
  private static final Base64.Decoder b64dec = Base64.getDecoder();

  // https://pki.goog/repository/
  //  Name 	gsr2
  //  Public Key 	RSA
  //  Fingerprint (SHA1) 	69:e2:d0:6c:30:f3:66:16:61:65:e9:1d:68:d1:ce:e5:cc:47:58:4a:80:22:7e:76:66:60:86:c0:10:72:41:eb
  //  Valid Until 	2021-12-15
  private static final String ANDROID_SAFETYNET_ROOT =
    "MIIDvDCCAqSgAwIBAgINAgPk9GHsmdnVeWbKejANBgkqhkiG9w0BAQUFADBMMSAwHgYDVQQLExdH" +
    "bG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv" +
    "YmFsU2lnbjAeFw0wNjEyMTUwODAwMDBaFw0yMTEyMTUwODAwMDBaMEwxIDAeBgNVBAsTF0dsb2Jh" +
    "bFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT" +
    "aWduMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAps8kDr4ubyiZRULEqz4hVJsL03+E" +
    "cPoSs8u/h1/Gf4bTsjBc1v2t8Xvc5fhglgmSEPXQU977e35ziKxSiHtKpspJpl6op4xaEbx6guu+" +
    "jOmzrJYlB5dKmSoHL7Qed7+KD7UCfBuWuMW5Oiy81hK561l94tAGhl9eSWq1OV6INOy8eAwImIRs" +
    "qM1LtKB9DHlN8LgtyyHK1WxbfeGgKYSh+dOUScskYpEgvN0L1dnM+eonCitzkcadG6zIy+jgoPQv" +
    "kItN+7A2G/YZeoXgbfJhE4hcn+CTClGXilrOr6vV96oJqmC93Nlf33KpYBNeAAHJSvo/pOoHAyEC" +
    "joLKA8KbjwIDAQABo4GcMIGZMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud" +
    "DgQWBBSb4gdXZxwewGoG3lm0mi3f3BmGLjAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmG" +
    "LjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L3Jvb3QtcjIuY3Js" +
    "MA0GCSqGSIb3DQEBBQUAA4IBAQANeX81Z1YqDIs4EaLjG0qPOxIzaJI/y4kiRj3a+y3KOx74clIk" +
    "LuMgi/9/5iv/n+1LyhGU9g7174slbzJOPbSpp1eT19ST2mYbdgTLx/hm3tTLoHIY/w4ZbnQYwfnP" +
    "wAG4RefnEFYPQJmpD+Wh8BJwBgtm2drTale/T6NBwmwnEFunfaMfMX3g6IBrx7VKnxIkJh/3p190" +
    "WveLKgl9n7i5SWce/4woPimEn9WfEQWRvp6wKhaCKFjuCMuulEZusoOUJ4LfJnXxcuQTgIrSnwI7" +
    "KfSSjsd42w3lX1fbgJp7vPmLM6OBRvAXuYRKTFqMAWbb7OaGIEE+cbxY6PDepnva";

  @Override
  public String fmt() {
    return "android-safetynet";
  }

  @Override
  public void validate(JsonObject webauthn, byte[] clientDataJSON, JsonObject attestation, AuthData authData) throws AttestationException {
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
      // response is a JWT
      JsonObject token = JWT.parse(attStmt.getBinary("response"));

      // verify the payload:
      // 1. Hash clientDataJSON using SHA256, to create clientDataHash
      byte[] clientDataHash = hash("SHA-256", clientDataJSON);
      // 2. Concatenate authData with clientDataHash to create nonceBase
      Buffer nonceBase = Buffer.buffer()
        .appendBytes(authData.getRaw())
        .appendBytes(clientDataHash);
      // 3. Hash nonceBase using SHA256 to create nonceBuffer.
      // 4. Check that “nonce” is set to expectedNonce
      if (!MessageDigest.isEqual(hash("SHA-256", nonceBase.getBytes()), b64dec.decode(token.getJsonObject("payload").getString("nonce")))) {
        throw new AttestationException("JWS nonce does not contains expected nonce!");
      }
      // 5. Check that “ctsProfileMatch” is set to true. If its not set to true, that means that device has been rooted
      // and so can not be trusted to provide trustworthy attestation.
      if (!token.getJsonObject("payload").getBoolean("ctsProfileMatch")) {
        throw new AttestationException("JWS ctsProfileMatch is false!");
      }

      // Verify the header
      JsonArray x5c = token.getJsonObject("header").getJsonArray("x5c");
      if (x5c == null || x5c.size() == 0) {
        throw new AttestationException("Invalid certificate chain");
      }

      List<X509Certificate> certChain = new ArrayList<>();

      for (int i = 0; i < x5c.size(); i++) {
        certChain.add(JWS.parseX5c(b64dec.decode(x5c.getString(i))));
      }

      // 1. Get leaf certificate of x5c certificate chain, decode it,
      // and check that it was issued for “attest.android.com”
      if (!"attest.android.com".equals(CertificateHelper.getCertInfo(certChain.get(0)).subject("CN"))) {
        throw new AttestationException("The common name is not set to 'attest.android.com'!");
      }
      // 2. Use the “GlobalSign Root CA — R2” from Google PKI directory.
      // Attach it to the end of header.x5c and try to verify it
      certChain.add(JWS.parseX5c((b64dec.decode(ANDROID_SAFETYNET_ROOT))));
      // validate the chain
      CertificateHelper.checkValidity(certChain);

      // Verify the signature
      verifySignature(
        PublicKeyCredential.valueOf(token.getJsonObject("header").getString("alg")),
        certChain.get(0),
        token.getBinary("signature"),
        token.getBinary("signatureBase"));

    } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new AttestationException(e);
    }
  }
}
