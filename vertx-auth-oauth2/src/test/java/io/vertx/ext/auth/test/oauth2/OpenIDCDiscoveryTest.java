package io.vertx.ext.auth.test.oauth2;

import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.providers.AzureADAuth;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.ext.auth.oauth2.providers.SalesforceAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class OpenIDCDiscoveryTest extends VertxTestBase {


  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

  @Test
  public void testGoogle() {
    GoogleAuth.discover(vertx, new OAuth2ClientOptions(), load -> {
      // will fail as there is no application config, but the parsing should have happened
      assertTrue(load.failed());
      assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      testComplete();
    });
    await();
  }

  @Test
  public void testMicrosoft() {
    AzureADAuth.discover(vertx, new OAuth2ClientOptions(), load -> {
      // will fail as there is no application config, but the parsing should have happened
      assertTrue(load.failed());
      assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      testComplete();
    });
    await();
  }

  @Test
  public void testSalesforce() {
    SalesforceAuth.discover(vertx, new OAuth2ClientOptions(), load -> {
      // will fail as there is no application config, but the parsing should have happened
      assertTrue(load.failed());
      assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      testComplete();
    });
    await();
  }
}
