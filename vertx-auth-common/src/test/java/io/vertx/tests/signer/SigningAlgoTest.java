package io.vertx.tests.signer;

import io.vertx.ext.auth.impl.jose.algo.SigningAlgorithm;
import org.junit.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;

public class SigningAlgoTest {

  @Test
  public void testHS256() throws Exception {
    InputStream keys = SigningAlgoTest.class.getClassLoader().getResourceAsStream("keystore.pkcs12");
    assertNotNull(keys);
    KeyStore store = KeyStore.getInstance("pkcs12");
    store.load(keys, "secret".toCharArray());
    SigningAlgorithm algo = SigningAlgorithm.create(store, "HmacSHA256", "secret".toCharArray());
    assertEquals("HmacSHA256", algo.name());
    byte[] bytes = algo.signer().sign("foo".getBytes(StandardCharsets.UTF_8));
    assertTrue(algo.signer().verify(bytes, "foo".getBytes()));
  }

  @Test
  public void testRSA() throws Exception {
    InputStream keys = SigningAlgoTest.class.getClassLoader().getResourceAsStream("keystore.pkcs12");
    assertNotNull(keys);
    KeyStore store = KeyStore.getInstance("pkcs12");
    store.load(keys, "secret".toCharArray());
    SigningAlgorithm algo = SigningAlgorithm.create(store, "HmacSHA384", "secret".toCharArray());
    assertEquals("HmacSHA384", algo.name());
    byte[] bytes = algo.signer().sign("foo".getBytes(StandardCharsets.UTF_8));
    assertTrue(algo.signer().verify(bytes, "foo".getBytes()));
  }
}
