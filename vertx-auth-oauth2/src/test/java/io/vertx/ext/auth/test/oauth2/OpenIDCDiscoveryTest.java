package io.vertx.ext.auth.test.oauth2;

import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class OpenIDCDiscoveryTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testGoogle(TestContext should) {
    final Async test = should.async();
    GoogleAuth.discover(rule.vertx(), new OAuth2Options(), load -> {
      // will fail as there is no application config, but the parsing should have happened
      should.assertTrue(load.failed());
      should.assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      test.complete();
    });
  }

  @Test
  public void testMicrosoft(TestContext should) {
    final Async test = should.async();
    AzureADAuth.discover(rule.vertx(), new OAuth2Options().setTenant("common"), load -> {
      // will fail as there is no application config, but the parsing should have happened
      should.assertTrue(load.failed());
      should.assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      test.complete();
    });
  }

  @Test
  public void testSalesforce(TestContext should) {
    final Async test = should.async();
    SalesforceAuth.discover(rule.vertx(), new OAuth2Options(), load -> {
      // will fail as there is no application config, but the parsing should have happened
      should.assertTrue(load.failed());
      should.assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
      test.complete();
    });
  }


  @Test
  public void testIBMCloud(TestContext should) {
    final Async test = should.async();
    IBMCloudAuth.discover(
      rule.vertx(),
      new OAuth2Options()
        .setSite("https://us-south.appid.cloud.ibm.com/oauth/v4/{tenant}")
        .setTenant("39a37f57-a227-4bfe-a044-93b6e6060b61"),
      load -> {
        // will fail as there is no application config, but the parsing should have happened
        should.assertTrue(load.failed());
        should.assertEquals("Not Found: {\"status\":404,\"error_description\":\"Invalid TENANT ID\",\"error_code\":\"INVALID_TENANTID\"}", load.cause().getMessage());
        test.complete();
      });
  }

  @Test
  @Ignore
  public void testAmazonCognito(TestContext should) {
    final Async test = should.async();
    AmazonCognitoAuth.discover(
      rule.vertx(),
      new OAuth2Options()
        .setSite("https://cognito-idp.eu-central-1.amazonaws.com/{tenant}")
        .setClientId("the-client-id")
        .setClientSecret("the-client-secret")
        .setTenant("user-pool-id"),
      load -> {
        // will fail as there is no application config, but the parsing should have happened
        test.complete();
      });
  }

  @Test
  public void testAzureConfigOverride(TestContext should) {
    final Async test = should.async();
    AzureADAuth.discover(
      rule.vertx(),
      new OAuth2Options()
        // force v2.0
        .setSite("https://login.microsoftonline.com/{tenant}/v2.0")
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setTenant("common")
        // for extra security enforce the audience validation
        .setJWTOptions(new JWTOptions()
          .addAudience("api://client-id")), discovery -> {

        should.assertTrue(discovery.succeeded());
        OAuth2Options config = ((OAuth2AuthProviderImpl) discovery.result()).getConfig();
        // should merge not override!
        JWTOptions jwtOptions = config.getJWTOptions();
        should.assertEquals("api://client-id", jwtOptions.getAudience().get(0));
        System.out.println(jwtOptions.getAudience());
        test.complete();
      });
  }
}
