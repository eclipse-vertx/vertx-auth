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
}
