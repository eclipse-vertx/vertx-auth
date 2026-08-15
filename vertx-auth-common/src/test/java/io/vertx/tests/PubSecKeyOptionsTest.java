package io.vertx.tests;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.jose.JWK;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Documents the JSON representation of {@link PubSecKeyOptions}: the {@code buffer} field is the base64 encoding
 * of the key bytes (a {@link Buffer} in JSON), not the PEM text itself.
 *
 * @see <a href="https://github.com/eclipse-vertx/vertx-auth/issues/596">#596</a>
 */
public class PubSecKeyOptionsTest {

  private static final String PEM =
    "-----BEGIN PUBLIC KEY-----\n" +
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEraVJ8CpkrwTPRCPluUDdwC6b8+m4\n" +
      "dEjwl8s+Sn0GULko+H95fsTREQ1A2soCFHS4wV3/23Nebq9omY3KuK9DKw==\n" +
      "-----END PUBLIC KEY-----";

  @Test
  public void testJsonRoundTrip() {
    PubSecKeyOptions original = new PubSecKeyOptions()
      .setAlgorithm("ES256")
      .setId("k1")
      .setBuffer(PEM);

    JsonObject json = original.toJson();
    // in JSON the buffer is base64 encoded, not the PEM text
    assertEquals(Base64.getEncoder().encodeToString(PEM.getBytes(StandardCharsets.UTF_8)), json.getString("buffer"));

    PubSecKeyOptions copy = new PubSecKeyOptions(json);
    assertEquals("ES256", copy.getAlgorithm());
    assertEquals("k1", copy.getId());
    assertEquals(PEM, copy.getBuffer().toString(StandardCharsets.UTF_8));
    assertEquals(original.toJson(), copy.toJson());
  }

  @Test
  public void testFromJsonWithBase64Pem() {
    JsonObject json = new JsonObject()
      .put("algorithm", "ES256")
      .put("buffer", Base64.getEncoder().encodeToString(PEM.getBytes(StandardCharsets.UTF_8)));

    PubSecKeyOptions options = new PubSecKeyOptions(json);
    assertEquals(PEM, options.getBuffer().toString(StandardCharsets.UTF_8));
    // and the key material is usable
    JWK jwk = new JWK(options);
    assertEquals("ES256", jwk.getAlgorithm());
    assertTrue(jwk.signingAlgorithm().canVerify());
    assertFalse(jwk.signingAlgorithm().canSign());
  }

  @Test
  public void testFromJsonWithRawPemIsRejected() {
    // raw PEM text is not a valid base64 encoded buffer, users must encode it first (see testFromJsonWithBase64Pem)
    JsonObject json = new JsonObject()
      .put("algorithm", "ES256")
      .put("buffer", PEM);

    assertThrows(IllegalArgumentException.class, () -> new PubSecKeyOptions(json));
  }
}
