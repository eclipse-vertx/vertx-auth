package io.vertx.ext.auth.jwt;

import org.junit.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unitary tests for the {@link Crypto} class.
 *
 * @author <a href="mailto:david@davidafsilva.pt">david</a>
 */
public class CryptoTest {

  @Test
  public void test_mac_signVerify() throws Exception {
    final Crypto crypto = getMac();
    final byte[] payload = "World!".getBytes(StandardCharsets.UTF_8);
    final byte[] hash = crypto.sign(payload);
    assertArrayEquals(Base64.getDecoder().decode("aNlISkpF3OORSLOWrmLonO+R/TREP/3ENb5UuEHjczE="), hash);
    assertTrue(crypto.verify(hash, payload));
  }

  @Test
  public void test_mac_concurrentSignVerify() throws Throwable {
    final Crypto crypto = getMac();
    final byte[] payload = "World!".getBytes(StandardCharsets.UTF_8);
    concurrentSignVerify(crypto, payload, "aNlISkpF3OORSLOWrmLonO+R/TREP/3ENb5UuEHjczE=");
  }

  @Test
  public void test_signature_signVerify() throws Exception {
    final Crypto crypto = getSignature();
    final byte[] payload = "World!".getBytes(StandardCharsets.UTF_8);
    final byte[] signature = crypto.sign(payload);
    assertArrayEquals(Base64.getDecoder().decode("Gncqp+4rDGS1fjU+qhIF1ky2m7HGS+LfcgWHffDQL97QJVRsiJy+ZKghTpy" +
        "ujIV+tX6KQDb5HJsR2tP7TwsUGHSvPyY8clZvrwlCshAWI6cpdRM2udIawvzwDu0iaCrfbwMQxeQvz53nX2AkPu" +
        "CSYE6fgpb9hi8xqzxDHheTwV8L2aBv1L9pVRy5yJCpWe4vMSqBOLajD+bKMD0evRc2v9gxr2ugJ1okSXu8RnOYA" +
        "zRcaNMl7R/YjR+i5jYUFjD1KrdYz+JsBVONKtZEYoY3IKJBTir/Wl6uqnGlDD0hMisRWpm8Umks1GbZTAFrJ5zM" +
        "ftb0ctQxXdzCf+YH5/57PQ=="), signature);
    assertTrue(crypto.verify(signature, payload));
  }

  @Test
  public void test_signature_concurrentSignVerify() throws Exception {
    final Crypto crypto = getSignature();
    final byte[] payload = "World!".getBytes(StandardCharsets.UTF_8);
    concurrentSignVerify(crypto, payload, "Gncqp+4rDGS1fjU+qhIF1ky2m7HGS+LfcgWHffDQL97QJVRsiJy+ZKghTpy" +
        "ujIV+tX6KQDb5HJsR2tP7TwsUGHSvPyY8clZvrwlCshAWI6cpdRM2udIawvzwDu0iaCrfbwMQxeQvz53nX2AkPu" +
        "CSYE6fgpb9hi8xqzxDHheTwV8L2aBv1L9pVRy5yJCpWe4vMSqBOLajD+bKMD0evRc2v9gxr2ugJ1okSXu8RnOYA" +
        "zRcaNMl7R/YjR+i5jYUFjD1KrdYz+JsBVONKtZEYoY3IKJBTir/Wl6uqnGlDD0hMisRWpm8Umks1GbZTAFrJ5zM" +
        "ftb0ctQxXdzCf+YH5/57PQ==");
  }

  private void concurrentSignVerify(final Crypto crypto, final byte[] payload,
      final String expected) throws Exception {
    final ExecutorService pool = Executors.newFixedThreadPool(8);
    final Collection<Throwable> exceptions = new ConcurrentLinkedQueue<>();
    final CountDownLatch initialLatch = new CountDownLatch(8);
    final CountDownLatch finalLatch = new CountDownLatch(8);
    IntStream.range(0, 8).forEach(i -> pool.submit(() -> {
      try {
        initialLatch.countDown();
        initialLatch.await(10, TimeUnit.SECONDS);
        if (i % 2 == 0) {
          assertArrayEquals("sign failed", Base64.getDecoder().decode(expected), crypto.sign(payload));
        } else {
          assertTrue("verify failed", crypto.verify(Base64.getDecoder().decode(expected), payload));
        }
      } catch (Throwable e) {
        e.printStackTrace();
        exceptions.add(e);
      } finally {
        finalLatch.countDown();
      }
    }));
    finalLatch.await();
    assertEquals(exceptions.stream()
        .map(Throwable::getMessage)
        .reduce("", (a, b) -> a + System.lineSeparator() + b), 0, exceptions.size());

  }

  private CryptoMac getMac() throws Exception {
    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("Hello".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    return new CryptoMac(mac);
  }

  private CryptoSignature getSignature() throws Exception {
    final KeyStore ks = KeyStore.getInstance("jks");
    try (final InputStream in = CryptoTest.class.getResourceAsStream("/gce.jks")) {
      ks.load(in, "notasecret".toCharArray());
    }
    final X509Certificate publicKey = (X509Certificate) ks.getCertificate("RS256");
    final PrivateKey privateKey = (PrivateKey) ks.getKey("RS256", "notasecret".toCharArray());
    return new CryptoSignature("SHA256withRSA", publicKey, privateKey);
  }
}
