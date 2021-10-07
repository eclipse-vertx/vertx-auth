package io.vertx.ext.auth.it;

import io.vertx.ext.auth.JWKTest;

public class JWKLegacyBase64Test extends JWKTest {

  static {
    System.setProperty("vertx.json.base64", "legacy");
  }

}
