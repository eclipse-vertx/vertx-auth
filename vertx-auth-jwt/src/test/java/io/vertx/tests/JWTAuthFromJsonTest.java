package io.vertx.tests;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A JWTAuth configured from JSON must behave exactly like one configured with the fluent setters. In JSON, the
 * {@code buffer} of a {@code PubSecKeyOptions} is the base64 encoding of the PEM (or secret) bytes.
 *
 * @see <a href="https://github.com/eclipse-vertx/vertx-auth/issues/596">#596</a>
 */
@RunWith(VertxUnitRunner.class)
public class JWTAuthFromJsonTest {

  private static final String PUBLIC_PEM =
    "-----BEGIN PUBLIC KEY-----\n" +
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEraVJ8CpkrwTPRCPluUDdwC6b8+m4\n" +
      "dEjwl8s+Sn0GULko+H95fsTREQ1A2soCFHS4wV3/23Nebq9omY3KuK9DKw==\n" +
      "-----END PUBLIC KEY-----";

  private static final String PRIVATE_PEM =
    "-----BEGIN PRIVATE KEY-----\n" +
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeRyEfU1NSHPTCuC9\n" +
      "rwLZMukaWCH2Fk6q5w+XBYrKtLihRANCAAStpUnwKmSvBM9EI+W5QN3ALpvz6bh0\n" +
      "SPCXyz5KfQZQuSj4f3l+xNERDUDaygIUdLjBXf/bc15ur2iZjcq4r0Mr\n" +
      "-----END PRIVATE KEY-----\n";

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static String base64(String pem) {
    return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  public void testTokenSignedWithSettersIsVerifiedByJsonConfig(TestContext should) {
    JWTAuth signer = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setBuffer(PRIVATE_PEM)));

    // the same public key, this time given as JSON, e.g. loaded from a config file
    JWTAuth verifier = JWTAuth.create(rule.vertx(), new JWTAuthOptions(new JsonObject()
      .put("pubSecKeys", new JsonArray()
        .add(new JsonObject()
          .put("algorithm", "ES256")
          .put("buffer", base64(PUBLIC_PEM))))));

    String token = signer.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions().setAlgorithm("ES256"));

    verifier.authenticate(new TokenCredentials(token))
      .onComplete(should.asyncAssertSuccess(user -> should.assertEquals("paulo", user.subject())));
  }

  @Test
  public void testJsonConfigIsIdenticalToSetterConfig() {
    JWTAuthOptions fromSetters = new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("ES256")
        .setBuffer(PUBLIC_PEM));

    JWTAuthOptions fromJson = new JWTAuthOptions(new JsonObject()
      .put("pubSecKeys", new JsonArray()
        .add(new JsonObject()
          .put("algorithm", "ES256")
          .put("buffer", base64(PUBLIC_PEM)))));

    org.junit.Assert.assertEquals(1, fromJson.getPubSecKeys().size());
    org.junit.Assert.assertEquals(fromSetters.getPubSecKeys().get(0).toJson(), fromJson.getPubSecKeys().get(0).toJson());
  }
}
