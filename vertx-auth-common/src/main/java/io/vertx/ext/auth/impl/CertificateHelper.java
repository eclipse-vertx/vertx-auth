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
package io.vertx.ext.auth.impl;

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class CertificateHelper {

  private static final Logger LOG = LoggerFactory.getLogger(CertificateHelper.class);

  public final static class CertInfo {

    private final Map<String, String> subject;
    private final int version;
    private final int basicConstraintsCA;

    private CertInfo(Map<String, String> subject, int version, int basicConstraintsCA) {
      this.subject = subject;
      this.version = version;
      this.basicConstraintsCA = basicConstraintsCA;
    }

    public boolean subjectHas(String key) {
      if (subject != null) {
        return subject.containsKey(key);
      }
      return false;
    }

    public String subject(String key) {
      if (subject != null) {
        return subject.get(key);
      }
      return null;
    }

    public int version() {
      return version;
    }

    public int basicConstraintsCA() {
      return basicConstraintsCA;
    }

    public boolean isEmpty() {
      if (subject != null) {
        return subject.isEmpty();
      } else {
        return true;
      }
    }
  }

  private CertificateHelper() {
  }

  public static void checkValidity(List<X509Certificate> certificates, List<X509CRL> crls) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
    checkValidity(certificates, true, crls);
  }

  public static void checkValidity(List<X509Certificate> certificates, boolean withRootCA, List<X509CRL> crls) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

    if (certificates == null || certificates.size() == 0) {
      throw new CertificateException("empty chain");
    }

    final long now = System.currentTimeMillis();

    for (int i = 0; i < certificates.size(); i++) {
      final X509Certificate subjectCert = certificates.get(i);
      subjectCert.checkValidity();
      // check if the certificate is revoked
      if (crls != null) {
        for (X509CRL crl : crls) {
          if (crl.getNextUpdate().getTime() < now) {
            LOG.warn("CRL is out of date nextUpdate < now");
          }
          if (crl.isRevoked(subjectCert)) {
            throw new CertificateException("Certificate is revoked");
          }
        }
      }

      // single certificate nothing else to be checked
      if (certificates.size() == 1) {
        return;
      }

      final X509Certificate issuerCert;

      if (i + 1 < certificates.size()) {
        issuerCert = certificates.get(i + 1);
        // verify that the issuer matches the next one in the list
        if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
          throw new CertificateException("Certificate path issuers dont match: [" + subjectCert.getIssuerX500Principal() + "] != [" + issuerCert.getSubjectX500Principal() + "]");
        }
        // verify the certificate against the issuer
        subjectCert.verify(issuerCert.getPublicKey());
      }
    }

    if (withRootCA) {
      // the last certificate should be self signed
      X509Certificate root = certificates.get(certificates.size() - 1);
      root.verify(root.getPublicKey());
    }
  }

  public static CertInfo getCertInfo(X509Certificate cert) {

    final String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    Map<String, String> sub = null;

    if (subject != null && !"".equals(subject)) {
      String[] values = subject.split(",");

      sub = new HashMap<>();

      for (String value : values) {
        int idx = value.indexOf('=');
        if (idx != -1) {
          sub.put(value.substring(0, idx), value.substring(idx + 1));
        } else {
          sub.put(value, null);
        }
      }
    }

    return new CertInfo(sub, cert.getVersion(), cert.getBasicConstraints());
  }
}
