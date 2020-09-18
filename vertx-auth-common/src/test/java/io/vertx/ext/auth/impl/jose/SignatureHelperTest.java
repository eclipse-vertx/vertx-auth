package io.vertx.ext.auth.impl.jose;

import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureHelperTest {

  @Test
  public void testSignatureHelper() {
    assertTrue(SignatureHelper.isASN1(Base64.getUrlDecoder().decode("MCYCEQDEMaWRBcGQuP-DtlsfNQBHAhEAszOqZ_37oJRbciOwWy3l5Q==")));
  }

  @Test
  public void testSignatureHelperNull() {
    assertFalse(SignatureHelper.isASN1(null));
  }

  @Test
  public void testSignatureHelperInvalid() {
    assertFalse(SignatureHelper.isASN1(Base64.getUrlDecoder().decode("MCYCEQDEMaWRBcGQuP-DtlsfNQBHAhEAszOqZ_37oJRbciOwWy3l5QMCYCE")));
  }
}
