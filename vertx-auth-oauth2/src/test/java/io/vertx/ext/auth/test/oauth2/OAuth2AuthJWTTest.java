package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.queryToJSON;

public class OAuth2AuthJWTTest extends VertxTestBase {

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 3600" +
      "}");

  protected OAuth2Auth oauth2;
  private HttpServer server;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = GoogleAuth.create(vertx, new JsonObject()
      .put("type", "service_account")
      .put("project_id", "jetdrone")
      .put("private_key_id", "03f52167fc059dd8b06fea829d5cf64eeed85d82")
      .put("private_key", "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+LyhQqgy0hkUt\ndJfcBs/dleD+486n8xQkzNl0doRQZ2mEA72uU4HE6q9cDXDJJFMOJsYuwmyj2Zk5\n90e+iWvWuV2DlXXH0mbCKlDajk4Kux6Z8XB8kVXGi3SjbiQ2CcoMe674ki2Yz0I7\n8VZy9vZ1rz3f2z8eFsUnL+ywF6TCvptYeLqCJJSEJhTOFrGHowHYagUucEhVIody\nrwWdHNyo4IguzgKJ/Ke1Aq5hZYRhJYiETD15TcbvT0yUTY96bIRSQzk5Z66S3AyC\nuai/UtKaJy5v8FcjpJuYutoy+zSgUj14Bhp/cvL8xgbypPwi3a9TAuFTzXBsORst\nUzvNh1IfAgMBAAECggEAXHSocK56hrhPoQ1xVfGp09stCjzNFjDBtjIv9MI5CK19\nSkRXTgwipgxBO8r87YvPJK4M4mZ6Uh1StC9WnXZJCpYKtBFQtNfARNw1ekp7/hOB\niO0q9iPhQyhAh8Lfr7WKmA74vLazm/oGBQYKNNGCdyu+NLltMb94ENjng6O64UDZ\nXJa5m1k0TqjBveu0B3ti8xYOKuO2expZieflWuW6g/9sPa1gqKauciVGkshleSpP\nKxV9fjlauQ2yUwI/4naPfOovCc8F0A+A6sDTCq66E2jZCwxr7xEahzU1fYPPnMZN\nXf8VaJxeDWsiUoJxSabmerH/icm6mubdiHUw07R04QKBgQDrnM4ECMB5zfeFtYZk\ncrVIMt1wpQJ/40Hn6bIntg7CancjqxYo4eOVVHVNy18ciiSB2ih7LdrmwjjzUsDb\nT0+NIM5kCOwlJPA7qzLY/G0p9iZfZlU0437OckXUHbnnyEyzygmU/AIQ7Mq2vM6B\njt+B0nDczRrRqD8Phf9rmq09nQKBgQDOpAr0z3DmKa/LDH/UVgSfNQyFnbHIEZPV\nh39tjHVDNY60uol8FDlpmaLfoy3GnCgCihcXRtykkW1LROt2lM3R2ZpG5yc8K7Nu\n7GdtiyasUdQIgXqNJ4UFbQo/PUJ69f5SM9k0KwICOIibBTwsYRSkmj80nDjFnlQJ\nJu+WqOTf6wKBgQDoWSEc/1h4hfJDzIh0xF4bjfWsIT2+ymjzABYtbS9O8Fj/NrfK\np0CcwcZQam8oIN7xoybqmoTVrdElu4TugV8M6L5ADkB6PNwfq6ugKgapK9IZoDwE\nxRgHFM/h51KuzWs+nc4nOwH6mNkrrjPjtfaZ+uJMDIQXH1jYwSbqgYW4TQKBgHdc\ninee27gXnFPNhIlCpqjQG8uSq37FqH9PJWxCFfoclbIPjhr+E6vL8yj7ORXgXbwZ\nx/zKEel9l4RC60Az9C+jYlpSa3d2Rs9r/tJn7o7bNX80S3X9vfjEY4bj++LK9XzG\nNlDMBv0BaucgvwFjkmkCMEBTfPep3SDsPLjqFkrBAoGBALaaBgulePsvrdNHDyt1\nS2VL/InoGGPHN/6NLYW/Nv8NYA+mhizyrFKwMYJIgrm09Z9Je7UQkYImrozfE7j3\nLaSWeXHy5kUjdJc458ile+Lzb4MyJ/ytu+BeGSdCvBZc/jZf8LpiLrGoIz+oDMWD\n0cC+r1OmFtjn4uy3S7MCmuKO\n-----END PRIVATE KEY-----\n")
      .put("client_email", "account-1@jetdrone.iam.gserviceaccount.com")
      .put("client_id", "100772279109966512281")
      .put("auth_uri", "https://accounts.google.com/o/oauth2/auth")
      // here i'm hacking to call the mock server, not google
      .put("token_uri", "http://localhost:8080/oauth2/v4/token")
      .put("auth_provider_x509_cert_url", "https://www.googleapis.com/oauth2/v1/certs")
      .put("client_x509_cert_url", "https://www.googleapis.com/robot/v1/metadata/x509/account-1%40jetdrone.iam.gserviceaccount.com"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth2/v4/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject payload = queryToJSON(buffer.toString());
            assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", payload.getString("grant_type"));
            assertNotNull(payload.getValue("assertion"));
          } catch (UnsupportedEncodingException e) {
            fail(e);
          }
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
        });
      } else {
        req.response().setStatusCode(400).end();
      }
    }).listen(8080, ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }
      // ready
      latch.countDown();
    });

    latch.await();

  }

  @Override
  public void tearDown() throws Exception {
    server.close();
    super.tearDown();
  }

  @Test
  public void getToken() {
    JsonObject jwt = new JsonObject()
      .put("scope", "https://www.googleapis.com/auth/devstorage.readonly");

    oauth2.authenticate(jwt, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        User token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());
        testComplete();
      }
    });
    await();
  }
}
