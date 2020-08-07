package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.queryToJSON;

public class OAuth2AuthJWTGoogleRegressionTest extends VertxTestBase {

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
      .put("project_id", "232232")
      .put("private_key_id", "f05415b13acb9590f70df862765c655f5a7a019e")
      .put("private_key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCcmsCeICRKgo2\nw8Uya5NEEzuywvJvjBwStzgldzPb1KLh/0PQVCmw2eY8H1x/y5D2k+uZjl4mn5m1\nWiTi0ZNPsvDfIDGrn4YuVRH74vgLnZ1R0bUo+eNeaPkKhk9MHty9nMo4BO7GnVWb\nL9yUEJvM703Hj7FgdmA2YnxIKmYcBduKBM8vvKmSSfJVIHFE2sZ4b9m8EkqpyA25\nhCVXpIBTpU0VlCQAXdZLrrOluEFBSr3AbIi+nr578MJ03WYVKAS7Ti5NEx0+jru2\nZV3HFaDGbRczwuck4OQ7BLvZ6CLDtbI3K4MzTmXvhY3zJQoa1NUzXB1t0jrSXecP\nciQMCDTbAgMBAAECggEAStqbIUdcTwW9CtoQdtl8xq8UwztS8uggAoBv59RcrVrN\nHW0UIQXVStSHUkvMYxHti07kWqe4zOuR04ORQZPmPr8nBO4y0NvHXty24J2+WVJi\ntpWhRNX11mlYvdl4e1hCJ+hM3IXhmaoFw4kIRCOkpp7U9Wb2pKjNXwJIz8sqpcxb\nG0AeJh+bcZpAPCnICGkzq39bx/DiBjBX/B2Tzc/m6XjQSTi6zI4gwdZPORhmn9QT\n2vGblAndmWc0oYVfkr+luaAb1V4vV+4hWsMoSvQx3l2BwqqXiA6qdivNAh5kNZdT\nEtlwNxcFIHmUa2hId/BciA+v0Gd1woUWz5DeM8074QKBgQDySwUB/3c1JgfBjIRH\nkf8bhOdBTD9NqWdQjwef5N4zrUWNq2/Aho6dL4rk65qME+vZySjc9QkFMc9m/AtN\ndO1axYN2va1bXqIV0VFhqO0h4y3Me3aIGYTgI6fkKIgRnI7anNw2m8aYuS1AlECl\njlNXh7KHA72yTeGjgrjVsjr7iwKBgQDNcnkTNf8pDwAF9XhPtSOHRGUovCny6iG+\nh/nEZY5UwOvmuVRfsCXOAhThbx98flOuY6Prsnm7U48TuZRCVDxSvlHSBNGp/MSG\nEIr3926dFGK2xi0JADx728v7PSL/q3Qn72sFMR/AZDueGcsy6tg+UXaMlLm5wulf\nLGlJ630V8QKBgFAYrrofWqgOP2gjbKNAR0YwpEY4z4B77PR7o/ierzoEIMcZkmLh\n2Ilr6w2MOVXvS/t9/W0179pwwfB4h7/+VGy6eKArSgC3gvuVa8LOFj4qnLxJYEDT\nttJl1x2crIat66enTUEcNAXOyX/cwpY4O6Lm8ASkHvSvvFTSZQn31nnLAoGBAIM2\nGR2r3sraSamEnNJLXeWGSRU7F4+M+QA2184XDlAS5pb0xm5Wkc6AhdV0oydfhxJZ\nkNd3pUd+lmKCo625Hs25v4fijAWE6f61kgvMe1jXLDSPXTPicr6oIh7TbQbc+dKH\nllI6jYzSd0ECOETMuE8UuCIQ2o1JbsLaGmSbgcgBAoGAVa4fpMEgEq47t++Ra1aa\nwnHot9j0bGJzLDe5GelCgbpy3Bkc4P0YwDCz8fhlZ7jOhsA0tweo9oD4GLK57Z2K\nQj0IENavvd1kSIV1W+y4BAWiqAFSAikvzLQX6dSJxrKOZksteT4+9iHP83NkzE+O\nTUZgeRKMHcGVCjyIEHCy3Pk=\n-----END PRIVATE KEY-----\n")
      .put("client_email", "ddddddddddddddd.iam.gserviceaccount.com")
      .put("client_id", "232323")
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
  public void getTokenGivenAnAccessTokenShouldNotBeAllowed() {
    JsonObject jwt = new JsonObject()
      .put("access_token", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYwNTQxNWIxM2FjYjk1OTBmNzBkZjg2Mjc2NWM2NTVmNWE3YTAxOWUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiNDYyNTUwMTE3ODY3LWRyYmtwY2oxcXY0bW5rbzFqMmVrczRyYmI4Z204dm9iLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiNDYyNTUwMTE3ODY3LWRyYmtwY2oxcXY0bW5rbzFqMmVrczRyYmI4Z204dm9iLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA1MTk3NjM5NzI4ODE0NzI0MjcwIiwiZW1haWwiOiJpbmplY3RlZXJAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJ1M0dhMHBEVXdRYTYyQTdTUFhyWmh3IiwibmFtZSI6IktvbnN0YW50aW4gU21pcm5vdiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS0vQU9oMTRHaXhrM1R4OEhaWnd0YlZWWEdKanE2b0c0V0otWV83N01MQ3pyd1Nvdz1zOTYtYyIsImdpdmVuX25hbWUiOiJLb25zdGFudGluIiwiZmFtaWx5X25hbWUiOiJTbWlybm92IiwibG9jYWxlIjoiZW4tR0IiLCJpYXQiOjE1OTY0NjYxMzUsImV4cCI6MTU5NjQ2OTczNSwianRpIjoiMjQ3NzkyYjI0NWNkZjE5ZDEzYTU3OTU1Nzg2MjdlNWUyN2E5ZmY1ZiJ9.LTAKctyEAkMa0AnrrJmMpi4Ifquq1zru_mg7FIqDQhrqJqlAQ5BqOjixVY194zfd3gdPGjISJKSL5TiqNg-uc7sG2d2XckdiuhRE2uawRpZlSIDTd7TfPZXJEWdPDPf9FQOFaVqyzaZGXWX4v6OzLuZ-DsL-esf2-YTkaImF0RHqoGXsPbzrULgK7LX9zV58mqurimhOF7S-eZyFX_Hqis5Nij3zvHJW6Y9KIxl-yPIO4ge6bGk6iD-A_4d5OuL5E0rL9RE4CWT783KGAPBnC1e5J8nhMhxoOJLh3eP_CSDuYDfe0WSid34JyRCd3ZW1VD3f0_PAeEMxkPyctfPQYA");

    oauth2.authenticate(jwt, res -> {
      if (res.failed()) {
        testComplete();
      } else {
        fail("JWT mode creates own tokens");
      }
    });
    await();
  }

  @Test
  public void getTokenGeneratingAServiceToken() {
    JsonObject jwt = new JsonObject()
      // https://developers.google.com/identity/protocols/oauth2/service-account#httprest_1
      .put("scope", "https://www.googleapis.com/auth/devstorage.read_only");

    oauth2.authenticate(jwt, res -> {
      if (res.failed()) {
        fail("JWT mode creates own tokens");
      } else {
        testComplete();
      }
    });
    await();
  }
}
