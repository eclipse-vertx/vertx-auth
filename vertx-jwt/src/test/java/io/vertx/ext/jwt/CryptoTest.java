package io.vertx.ext.jwt;

import io.vertx.ext.auth.PubSecKeyOptions;
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

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.*;

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

  @Test
  public void ecdsaSignatureComplianceTest() throws Exception {

    JWT jwt = new JWT()
      .addJWK(new JWK(
        new PubSecKeyOptions()
          .setAlgorithm("ES512")
          .setBuffer("-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQASisgweVL1tAtIvfmpoqvdXF8sPKTV9YTKNxBwkdkm+/auh4pR8TbaIfsEzcsGUVv61DFNFXb0ozJfurQ59G2XcgAn3vROlSSnpbIvuhKrzL5jwWDTaYa5tVF1Zjwia/5HUhKBkcPuWGXg05nMjWhZfCuEetzMLoGcHmtvabugFrqsAg=\n-----END PUBLIC KEY-----\n")));

    assertFalse(jwt.isUnsecure());
    //Test verification for token created using https://github.com/auth0/node-jsonwebtoken/tree/v7.0.1
    assertNotNull(jwt.decode("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30.Aab4x7HNRzetjgZ88AMGdYV2Ml7kzFbl8Ql2zXvBores7iRqm2nK6810ANpVo5okhHa82MQf2Q_Zn4tFyLDR9z4GAcKFdcAtopxq1h8X58qBWgNOc0Bn40SsgUc8wOX4rFohUCzEtnUREePsvc9EfXjjAH78WD2nq4tn-N94vf14SncQ"));
    //Test verification for token created using https://github.com/jwt/ruby-jwt/tree/v1.5.4
    assertNotNull(jwt.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoidGVzdCJ9.AV26tERbSEwcoDGshneZmhokg-tAKUk0uQBoHBohveEd51D5f6EIs6cskkgwtfzs4qAGfx2rYxqQXr7LTXCNquKiAJNkTIKVddbPfped3_TQtmHZTmMNiqmWjiFj7Y9eTPMMRRu26w4gD1a8EQcBF-7UGgeH4L_1CwHJWAXGbtu7uMUn"));
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
