package io.vertx.tests;

import io.vertx.ext.auth.impl.jose.JWS;
import io.vertx.ext.auth.webauthn.impl.WellKnownRootCertificates;
import org.junit.Test;

import java.security.cert.CertificateException;

public class TestRootCertificates {

  @Test
  public void testExtractCRL() throws CertificateException {
    for (WellKnownRootCertificates x509 : WellKnownRootCertificates.values()) {
      System.out.println(x509.name() + " " + JWS.extractCRLs(x509.certificate()));
    }
  }
}
