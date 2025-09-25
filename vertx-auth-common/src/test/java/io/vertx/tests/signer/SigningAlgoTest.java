package io.vertx.tests.signer;

import io.vertx.ext.auth.impl.jose.algo.SigningAlgorithm;
import org.junit.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static org.junit.Assert.*;

public class SigningAlgoTest {

  @Test
  public void testHS256() throws Exception {
    testAlgo("HmacSHA256", "HmacSHA256");
    testAlgo("HmacSHA384", "HmacSHA384");
    testAlgo("HmacSHA512", "HmacSHA512");
  }

  @Test
  public void testRSA() throws Exception {
    testAlgo("SHA256withRSA", "SHA256withRSA");
    testAlgo("SHA384withRSA", "SHA384withRSA");
    testAlgo("SHA512withRSA", "SHA512withRSA");
  }

  @Test
  public void testECDSA() throws Exception {
    testAlgo("SHA256withECDSA", "SHA256withECDSA");
    testAlgo("SHA384withECDSA", "SHA384withECDSA");
    testAlgo("SHA512withECDSA", "SHA512withECDSA");
  }

  private void testAlgo(String alias, String expectedName) throws Exception {
    InputStream keys = SigningAlgoTest.class.getClassLoader().getResourceAsStream("keystore.pkcs12");
    assertNotNull(keys);
    KeyStore store = KeyStore.getInstance("pkcs12");
    store.load(keys, "secret".toCharArray());
    KeyStore.Entry entry = store.getEntry(alias, new KeyStore.PasswordProtection("secret".toCharArray()));
    SigningAlgorithm algo = SigningAlgorithm.create(entry);
    assertEquals(expectedName, algo.name());
    byte[] signature = algo.signer().sign("foo".getBytes(StandardCharsets.UTF_8));
    assertTrue(algo.verifier().verify(signature, "foo".getBytes()));
  }
}
