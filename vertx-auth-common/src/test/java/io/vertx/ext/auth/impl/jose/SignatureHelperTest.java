package io.vertx.ext.auth.impl.jose;

import org.junit.Test;

import java.security.cert.CertificateException;
import java.util.Base64;

import static org.junit.Assert.*;

public class SignatureHelperTest {

  @Test
  public void testSignatureHelper() {
    assertTrue(JWS.isASN1(Base64.getUrlDecoder().decode("MCYCEQDEMaWRBcGQuP-DtlsfNQBHAhEAszOqZ_37oJRbciOwWy3l5Q==")));
  }

  @Test
  public void testSignatureHelperNull() {
    assertFalse(JWS.isASN1(null));
  }

  @Test
  public void testSignatureHelperInvalid() {
    assertFalse(JWS.isASN1(Base64.getUrlDecoder().decode("MCYCEQDEMaWRBcGQuP-DtlsfNQBHAhEAszOqZ_37oJRbciOwWy3l5QMCYCE")));
  }

  @Test
  public void testES256Signature() {
    byte[] signature = Base64.getUrlDecoder().decode("tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA");
    assertFalse(JWS.isASN1(signature));
    byte[] asn1 = JWS.toASN1(signature);
    assertTrue(JWS.isASN1(asn1));
    assertArrayEquals(signature, JWS.toJWS(asn1, 64));
  }

  @Test
  public void testES384Signature() {
    byte[] signature = Base64.getUrlDecoder().decode("cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN");
    assertFalse(JWS.isASN1(signature));
    byte[] asn1 = JWS.toASN1(signature);
    assertTrue(JWS.isASN1(asn1));
    assertArrayEquals(signature, JWS.toJWS(asn1, 96));
  }

  @Test
  public void testES512Signature() {
    byte[] signature = Base64.getUrlDecoder().decode("AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu");
    assertFalse(JWS.isASN1(signature));
    byte[] asn1 = JWS.toASN1(signature);
    assertTrue(JWS.isASN1(asn1));
    assertArrayEquals(signature, JWS.toJWS(asn1, 132));
  }

  @Test
  public void parseX5c() throws CertificateException {
    JWS.parseX5c("MIID1zCCAr+gAwIBAgIPBHHuTg2or5b9P/YXma/CMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSkwJwYDVQQDDCBGSURPIEFsbGlhbmNlcyBGQUtFIFJvb3QgQ0EgLSBTMTAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMFAxCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSkwJwYDVQQDDCBGSURPIEFsbGlhbmNlcyBGQUtFIFJvb3QgQ0EgLSBTMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmjPyFJ5QJSz9Fhdi4eF5u70nP1Bgdw/XD/f8JXDor81Q9kzEmJu/hBHWZ8cNJlIqDUBrO4rgMq0987hNuctm0wqMA98f5inD2f2TZ3aqnAvIRvDggKpkxZSPF9Mb6243cYu3ZvERvwpwx+3KMBHaWiGCKZSiebR553UYcVOlfKfmVcLoc4Tg7SyAlkRaHRbe1k/qqhiQ+KiYMo6BLTs9OTXa02FHD9zfHEcniYIeT1CH3dUX5FfzYzXc17zaJ1Kp0ylFzauz67IiRWi4KjB6xHFhkwEX4p1fGQEvNQrF8FQdo3lnRwbag9MiM4xugx9UikgFenDopvwWBwGfvDBHECAwEAAaOBrTCBqjALBgNVHQ8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHQ4EGAQWwhSqNv9BadKdijvYHGXTW95rcC2UkDAfBgNVHSMEGDAWgBSqNv9BadKdijvYHGXTW95rcC2UkDBIBgNVHR8EQTA/MD2gO6A5hjdodHRwczovL2ZpZG9hbGxpYW5jZS5jby5uei9zYWZldHluZXRwa2kvY3JsL3Jvb3QtczEuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAtT1x/AGZrSL+N42YTcMGzrQX+0gytCvbwdjUtarjtFMCl6U3ZnS2It/DBpwf1V3uIGZAvfUHflOcz/Mn+SiBWCj887y5W852Dxq3MFpuhWSMsFzeHElwaDhivUlrhK/+zyfUM2ze5fjsBmaF2Z2CstjnGTZtjvTW8mh3uYu3S39W6Dc1cS1Xvbcn6NwSdFp2zvtwEUUy5Bt2aMS+wLVSVxryqj6hwpcZsg5euUM8qL+MNBVX/p3vlN0VSqviRRauPlbb7QgKG4k/GYPVDjfG026LQ77MeVL7LBWtw/QOIbEe6i5xGGXFkvy/BFyeJg2VeZUb4TsCsfyAhvLnQKDS6");
    JWS.parseX5c("MIIDvDCCAqSgAwIBAgINAgPk9GHsmdnVeWbKejANBgkqhkiG9w0BAQUFADBMMSAwHgYDVQQLExdH" +
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
      "KfSSjsd42w3lX1fbgJp7vPmLM6OBRvAXuYRKTFqMAWbb7OaGIEE+cbxY6PDepnva");
  }
}
