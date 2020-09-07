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

import javax.security.auth.x500.X500Principal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class CertificateHelper {

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
  }

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

  public static CertInfo getCertInfo(X509Certificate cert) {

    final String subject = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    Map<String, String> sub = null;

    if (subject != null) {
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
