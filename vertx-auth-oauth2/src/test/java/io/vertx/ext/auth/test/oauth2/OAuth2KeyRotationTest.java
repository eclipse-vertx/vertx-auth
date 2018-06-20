package io.vertx.ext.auth.test.oauth2;

import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class OAuth2KeyRotationTest extends VertxTestBase {


  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testLoadJWK() {
    OAuth2Auth oauth2 = GoogleAuth.create(vertx, "", "");

    oauth2.loadJWK(load -> {
      assertFalse(load.failed());
      testComplete();
    });
    await();
  }


  @Test
  public void testLoadJWK2() {
    JsonObject config = new JsonObject("{\n" +
      "  \"realm\": \"master\",\n" +
      "  \"auth-server-url\": \"http://localhost:8080/auth\",\n" +
      "  \"ssl-required\": \"external\",\n" +
      "  \"resource\": \"test\",\n" +
      "  \"credentials\": {\n" +
      "    \"secret\": \"b0568625-a482-45d8-af8b-27beba502ed3\"\n" +
      "  }\n" +
      "}");

    OAuth2Auth oauth2 = KeycloakAuth.create(vertx, config);

    oauth2.loadJWK(load -> {
      assertFalse(load.failed());
      testComplete();
    });
    await();

  }
}
