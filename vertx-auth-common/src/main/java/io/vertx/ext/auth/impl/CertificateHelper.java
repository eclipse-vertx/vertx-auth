package io.vertx.ext.auth.impl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public final class CertificateHelper {

  private CertificateHelper() {}


  public static void checkValidity(List<X509Certificate> certificates) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

    for (int i = 0; i < certificates.size(); i++) {
      final X509Certificate subjectCert = certificates.get(i);
      subjectCert.checkValidity();

      // single certificate nothing else to be checked
      if (certificates.size() == 1) {
        return;
      }

      final X509Certificate issuerCert;

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
}
