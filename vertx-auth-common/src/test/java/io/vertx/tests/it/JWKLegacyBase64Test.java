package io.vertx.tests.it;

import io.vertx.tests.JWKTest;

public class JWKLegacyBase64Test extends JWKTest {

  static {
    System.setProperty("vertx.json.base64", "legacy");
  }

}
