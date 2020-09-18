package io.vertx.ext.auth.impl.jose;

import org.junit.Test;

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
}
