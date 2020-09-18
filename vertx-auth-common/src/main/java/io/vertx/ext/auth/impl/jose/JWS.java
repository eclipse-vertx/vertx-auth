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

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Utilities to work with Json Web Signatures.
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
public final class JWS {

  public static final String ES256 = "ES256";
  public static final String ES384 = "ES384";
  public static final String ES512 = "ES512";

  public static final String PS256 = "PS256";
  public static final String PS384 = "PS384";
  public static final String PS512 = "PS512";

  public static final String ES256K = "ES256K";

  public static final String RS256 = "RS256";
  public static final String RS384 = "RS384";
  public static final String RS512 = "RS512";

  public static final String RS1 = "RS1";

  private static final CertificateFactory X509;

  static {
    try {
      X509 = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  public static Signature getSignature(String alg) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    Signature sig;

    switch (alg) {
      case ES256:
      case ES256K:
        return Signature.getInstance("SHA256withECDSA");
      case ES384:
        return Signature.getInstance("SHA384withECDSA");
      case ES512:
        return Signature.getInstance("SHA512withECDSA");
      case RS256:
        return Signature.getInstance("SHA256withRSA");
      case RS384:
        return Signature.getInstance("SHA384withRSA");
      case RS512:
        return Signature.getInstance("SHA512withRSA");
      case RS1:
        return Signature.getInstance("SHA1withRSA");
      case PS256:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1));
        return sig;
      case PS384:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 384 / 8, 1));
        return sig;
      case PS512:
        sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1));
        return sig;
      default:
        throw new NoSuchAlgorithmException();
    }
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
      throw new SignatureException("Cannot validate signature one of {alg, certificate, signature, data} is null");
    }

    switch (alg) {
      case ES256:
      case ES384:
      case ES512:
      case ES256K:
        // JCA requires ASN1 encoded signatures!
        if (!SignatureHelper.isASN1(signature)) {
          signature = SignatureHelper.toASN1(signature);
        }
        break;
    }

    Signature sig = getSignature(alg);

    sig.initVerify(certificate);
    sig.update(data);

    return sig.verify(signature);
  }

  public static int getSignatureLength(String alg, PublicKey publicKey) throws NoSuchAlgorithmException {
    if (publicKey instanceof RSAKey) {
      return ((RSAKey) publicKey).getModulus().bitLength() + 7 >> 3;
    } else {
      switch (alg) {
        case ES256:
        case ES256K:
          return 64;
        case ES384:
          return 96;
        case ES512:
          return 132;
        case RS1:
        case RS256:
        case PS256:
          return 256;
        case RS384:
        case PS384:
          return 384;
        case RS512:
        case PS512:
          return 512;
        default:
          throw new NoSuchAlgorithmException();
      }
    }
  }

  public static X509Certificate parseX5c(byte[] data) throws CertificateException {
    return (X509Certificate) X509.generateCertificate(new ByteArrayInputStream(data));
  }
}
