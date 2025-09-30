/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.impl.jose;

import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.ext.auth.impl.asn.ASN1;
import io.vertx.ext.auth.impl.jose.algo.Signer;
import io.vertx.ext.auth.impl.jose.algo.SigningAlgorithm;
import io.vertx.ext.auth.impl.jose.algo.Verifier;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAKey;

import static io.vertx.ext.auth.impl.asn.ASN1.*;

/**
 * Utilities to work with Json Web Signatures.
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
public final class JWS {

  private static final String ES256 = "ES256";
  private static final String ES384 = "ES384";
  private static final String ES512 = "ES512";
  private static final String ES256K = "ES256K";
  private static final String RS256 = "RS256";
  private static final String HS256 = "HS256";

  private static final Logger LOG = LoggerFactory.getLogger(JWS.class);


  private static final CertificateFactory X509;

  static {
    try {
      X509 = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  private final JWK jwk;
  private Signer signer;
  private Verifier verifier;

  public JWS(JWK jwk) {
    if (jwk.use() != null && !"sig".equals(jwk.use())) {
      throw new IllegalArgumentException("JWK isn't meant to perform JWS operations");
    }

    try {
      SigningAlgorithm sa = jwk.signingAlgorithm();
      if (sa != null && sa.canSign()) {
        signer = sa.signer();
      }
      if (sa != null && sa.canVerify()) {
        verifier = sa.verifier();
      }
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }

    this.jwk = jwk;
  }

  public byte[] sign(byte[] payload) {
    if (payload == null) {
      throw new NullPointerException("payload is missing");
    }
    try {
      return signer.sign(payload);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public boolean verify(byte[] expected, byte[] payload) {
    if (expected == null) {
      throw new NullPointerException("signature is missing");
    }
    if (payload == null) {
      throw new NullPointerException("payload is missing");
    }
    try {
      return verifier.verify(expected, payload);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }
  }

  public JWK jwk() {
    return jwk;
  }

  /**
   * Verify if the data provider matches the signature based of the given certificate.
   *
   * @param certificate - origin certificate
   * @param signature   - received signature
   * @param data        - data to verify
   */
  public static boolean verifySignature(String alg, X509Certificate certificate, byte[] signature, byte[] data) throws InvalidKeyException, SignatureException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {

    if (alg == null || certificate == null || signature == null || data == null) {
      throw new SignatureException("Cannot validate signature, one of {alg, certificate, signature, data} is null");
    }

    switch (alg) {
      case ES256:
      case ES384:
      case ES512:
      case ES256K:
        // JCA requires ASN1 encoded signatures!
        if (!isASN1(signature)) {
          signature = toASN1(signature);
        }
        break;
    }

    Signature sig = getSignature(alg);

    if (sig == null) {
      throw new SignatureException("Cannot get a signature for: " + alg);
    }

    sig.initVerify(certificate);
    sig.update(data);

    return sig.verify(signature);
  }

  static int getSignatureLength(Alg alg, PublicKey publicKey) {
    if (publicKey instanceof RSAKey) {
      return ((RSAKey) publicKey).getModulus().bitLength() + 7 >> 3;
    } else {
      switch (alg) {
        case EdDSA:
        case ES256:
        case ES256K:
          return 64;
        case ES384:
          return 96;
        case ES512:
          return 132;
        case HS256:
        case RS1:
        case RS256:
        case PS256:
          return 256;
        case HS384:
        case RS384:
        case PS384:
          return 384;
        case HS512:
        case RS512:
        case PS512:
          return 512;
        default:
          throw new UnsupportedOperationException("Cannot determine length of algorithm " + alg);
      }
    }
  }

  public static X509Certificate parseX5c(String data) throws CertificateException {
    final X509Certificate certificate =
      (X509Certificate) X509.generateCertificate(
        new ByteArrayInputStream(addBoundaries(data, "CERTIFICATE").getBytes(StandardCharsets.UTF_8)));

    if (LOG.isDebugEnabled()) {
      String crl = extractCRLs(certificate);
      if (crl != null) {
        LOG.debug("CRL Distribution Point: " + crl);
      }
    }
    return certificate;
  }

  public static X509Certificate parseX5c(byte[] data) throws CertificateException {
    final X509Certificate certificate =
      (X509Certificate) X509.generateCertificate(new ByteArrayInputStream(data));

    if (LOG.isDebugEnabled()) {
      String crl = extractCRLs(certificate);
      if (crl != null) {
        LOG.debug("CRL Distribution Point: " + crl);
      }
    }
    return certificate;
  }

  public static String extractCRLs(X509Certificate certificate) throws CertificateException {
    if (certificate != null) {
      byte[] crlExtension = certificate.getExtensionValue("2.5.29.31");
      if (crlExtension != null) {
        // OCTET STRING
        ASN1.ASN extension = ASN1.parseASN1(crlExtension);
        if (!extension.is(OCTET_STRING)) {
          throw new CertificateException("2.5.29.31 Extension is not an ASN.1 OCTET STRING!");
        }
        // parse the octet as ASN.1 and expect it to be a sequence
        extension = parseASN1(extension.binary(0));
        //        SEQUENCE
        if (!extension.is(SEQUENCE)) {
          throw new CertificateException("2.5.29.31 Extension is not an ASN.1 SEQUENCE!");
        }

        ASN1.ASN crlDistributionPoint;
        for (int i = 0; i < extension.length(); i++) {
          //        SEQUENCE
          //          [0] (1 elem) distributionPoint <optional>
          //          [0] (1 elem) reasons  <optional>
          //          [6] (55 byte) cRLIssuer  <optional>
          crlDistributionPoint = extension.object(i, SEQUENCE);

          ASN1.ASN crlIssuer =
            crlDistributionPoint
              .object(0)
              .object(0)
              .object(0, CONTEXT_SPECIFIC | OBJECT_IDENTIFIER);

          if (crlIssuer != null) {
            return new String(crlIssuer.binary(0), StandardCharsets.US_ASCII);
          }
        }
      }
    }

    return null;
  }

  public static X509CRL parseX5crl(String data) throws CRLException {
    return (X509CRL) X509
      .generateCRL(
        new ByteArrayInputStream(addBoundaries(data, "X509 CRL").getBytes(StandardCharsets.UTF_8)));
  }

  public static X509CRL parseX5crl(byte[] data) throws CRLException {
    return (X509CRL) X509.generateCRL(new ByteArrayInputStream(data));
  }

  private static boolean byteAtIndexIs(byte[] data, int idx, int expected) {
    if (data == null) {
      return false;
    }
    if (data.length <= idx) {
      return false;
    }
    return Byte.toUnsignedInt(data[idx]) == expected;
  }

  private static boolean byteAtIndexLte(byte[] data, int idx, int expected) {
    if (data == null) {
      return false;
    }
    if (data.length <= idx) {
      return false;
    }
    if (data[idx] <= 0) {
      return false;
    }
    return Byte.toUnsignedInt(data[idx]) <= expected;
  }

  /**
   * A signature in ASN1 format is a sequence of 2 values.
   * This method verifies that the content contains the right markers and length.
   */
  public static boolean isASN1(byte[] sig) {
    // seq
    if (!byteAtIndexIs(sig, 0, 48)) {
      return false;
    }

    int offset;

    if (sig.length < 128) {
      offset = 0;
    } else {
      // handle extended
      if (!byteAtIndexIs(sig, 1, 0x81)) {
        return false;
      }
      offset = 1;
    }

    // sequence

    // verify the sequence byte length
    if (!byteAtIndexIs(sig, offset + 1, sig.length - offset - 2)) {
      return false;
    }

    offset = offset + 2;

    for (int i = 0; i < 2; i++) {
      // element [0]
      // check if the tag is 2 (integer)
      if (!byteAtIndexIs(sig, offset, 2)) {
        return false;
      }
      // verify the sequence[0] byte length
      if (!byteAtIndexLte(sig, offset + 1, sig.length - offset - 2)) {
        return false;
      }
      // element [1]
      offset = offset + sig[offset + 1] + 2;
    }

    return offset == sig.length;
  }

  /**
   * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
   * R + S format expected by ECDSA JWS.
   *
   * @param derSignature    The ASN1./DER-encoded. Must not be {@code null}.
   * @param signatureLength The length for the JWS signature.
   * @return The ECDSA JWS encoded signature.
   * @throws RuntimeException If the ASN.1/DER signature format is invalid.
   */
  public static byte[] toJWS(final byte[] derSignature, int signatureLength) {

    if (derSignature.length < 8 || derSignature[0] != 48) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    int offset;
    if (derSignature[1] > 0) {
      offset = 2;
    } else if (derSignature[1] == (byte) 0x81) {
      offset = 3;
    } else {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    byte rLength = derSignature[offset + 1];

    int i = rLength;
    while ((i > 0)
      && (derSignature[(offset + 2 + rLength) - i] == 0))
      i--;

    byte sLength = derSignature[offset + 2 + rLength + 1];

    int j = sLength;
    while ((j > 0)
      && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0))
      j--;

    int rawLen = Math.max(i, j);
    rawLen = Math.max(rawLen, signatureLength / 2);

    if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
      || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
      || derSignature[offset] != 2
      || derSignature[offset + 2 + rLength] != 2) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    final byte[] concatSignature = new byte[2 * rawLen];

    System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
    System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

    return concatSignature;
  }

  /**
   * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
   * the JCA verifier.
   *
   * @param jwsSignature The JWS signature, consisting of the
   *                     concatenated R and S values. Must not be
   *                     {@code null}.
   * @return The ASN.1/DER encoded signature.
   * @throws RuntimeException If the ECDSA JWS signature format is invalid.
   */
  public static byte[] toASN1(byte[] jwsSignature) {

    int rawLen = jwsSignature.length / 2;

    int i = rawLen;

    while ((i > 0)
      && (jwsSignature[rawLen - i] == 0))
      i--;

    int j = i;

    if (jwsSignature[rawLen - i] < 0) {
      j += 1;
    }

    int k = rawLen;

    while ((k > 0)
      && (jwsSignature[2 * rawLen - k] == 0))
      k--;

    if (k == 0) {
      throw new RuntimeException("Invalid ECDSA signature");
    }

    int l = k;

    if (jwsSignature[2 * rawLen - k] < 0) {
      l += 1;
    }

    int len = 2 + j + 2 + l;

    if (len > 255) {
      throw new RuntimeException("Invalid ECDSA signature format");
    }

    int offset;

    final byte[] derSignature;

    if (len < 128) {
      derSignature = new byte[2 + 2 + j + 2 + l];
      offset = 1;
    } else {
      derSignature = new byte[3 + 2 + j + 2 + l];
      derSignature[1] = (byte) 0x81;
      offset = 2;
    }

    derSignature[0] = 48;
    derSignature[offset++] = (byte) len;
    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) j;

    System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

    offset += j;

    derSignature[offset++] = 2;
    derSignature[offset++] = (byte) l;

    System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

    return derSignature;
  }


  private static String addBoundaries(final String certificate, final String boundary) {
    final String CERT_BOUNDARY_BEGIN = "-----BEGIN " + boundary + "-----\n";
    final String CERT_BOUNDARY_END = "\n-----END " + boundary + "-----\n";

    if (certificate.contains(CERT_BOUNDARY_BEGIN) && certificate.contains(CERT_BOUNDARY_END)) {
      // already done
      return certificate;
    }

    return
      CERT_BOUNDARY_BEGIN +
        certificate +
        CERT_BOUNDARY_END;
  }

  public static Signature getSignature(String alg) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    Alg algo;
    try {
      algo = Alg.valueOf(alg);
    } catch (IllegalArgumentException e) {
      throw new NoSuchAlgorithmException(alg);
    }
    try {
      return algo.signatureProvider != null ? algo.signatureProvider.call() : null;
    } catch (Exception e) {
      return null;
    }
  }
}
