package io.vertx.tests;

import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
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
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testGoogle(TestContext should) {
    final Async test = should.async();
    GoogleAuth.discover(rule.vertx(), new OAuth2Options())
      .onComplete(load -> {
        // will fail as there is no application config, but the parsing should have happened
        should.assertTrue(load.failed());
        should.assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
        test.complete();
      });
  }

  @Test
  public void testMicrosoft(TestContext should) {
    final Async test = should.async();
    AzureADAuth.discover(rule.vertx(), new OAuth2Options().setTenant("common"))
      .onComplete(load -> {
        // will fail as there is no application config, but the parsing should have happened
        should.assertTrue(load.failed());
        should.assertEquals("Configuration missing. You need to specify [clientId]", load.cause().getMessage());
        test.complete();
      });
  }

  @Test
  public void testSalesforce(TestContext should) {
    final Async test = should.async();
    SalesforceAuth.discover(rule.vertx(), new OAuth2Options())
      .onComplete(load -> {
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
          .setTenant("39a37f57-a227-4bfe-a044-93b6e6060b61"))
      .onComplete(load -> {
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
          .setTenant("user-pool-id"))
      .onComplete(load -> {
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
            .addAudience("api://client-id")))
      .onComplete(discovery -> {

        should.assertTrue(discovery.succeeded());
        OAuth2Options config = ((OAuth2AuthProviderImpl) discovery.result()).getConfig();
        // should merge not override!
        JWTOptions jwtOptions = config.getJWTOptions();
        should.assertEquals("api://client-id", jwtOptions.getAudience().get(0));
        test.complete();
      });
  }

  @Test
  public void testApple(TestContext should) {
    final Async test = should.async();

    AppleIdAuth.discover(
        rule.vertx(),
        new PubSecKeyOptions()
          .setAlgorithm("ES256")
          .setId("9K48F5P6SW")
          .setBuffer(Buffer.buffer(
            "-----BEGIN PRIVATE KEY-----\n" +
              "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2Pv8N3waHrH6WU5a\n" +
              "87SA17FZpLtZYXFYfTnMwBiZ5Z+gCgYIKoZIzj0DAQehRANCAATECgHrChq5ccqj\n" +
              "2sKF8BmJEKgHefk5ueM02dCrp4A/Y/5E9J84sE5e1ScJbasH3zuk2C09eGyQFyf2\n" +
              "wT6tSjSz\n" +
              "-----END PRIVATE KEY-----"
          )),
        new OAuth2Options()
          .setClientId("ca.weblite.signindemosvc")
          .setTenant("HRNMHC7527"))
      .onSuccess(load -> test.complete())
      .onFailure(should::fail);
  }

  /**
   * Asserts that the endpoints advertised by the provider discovery document match the endpoints hardcoded by the
   * provider {@code create()} shortcut. Discovery stores absolute URLs while the shortcuts store the site plus a
   * relative path, so relative paths are resolved before comparing. Endpoints omitted from the discovery document
   * are not compared.
   */
  private static void assertSameEndpoints(TestContext should, OAuth2Options expected, OAuth2Options discovered) {
    should.assertEquals(expected.getSite(), discovered.getSite());
    assertSameEndpoint(should, expected, expected.getAuthorizationPath(), discovered.getAuthorizationPath());
    assertSameEndpoint(should, expected, expected.getTokenPath(), discovered.getTokenPath());
    assertSameEndpoint(should, expected, expected.getUserInfoPath(), discovered.getUserInfoPath());
    assertSameEndpoint(should, expected, expected.getRevocationPath(), discovered.getRevocationPath());
    assertSameEndpoint(should, expected, expected.getIntrospectionPath(), discovered.getIntrospectionPath());
    assertSameEndpoint(should, expected, expected.getLogoutPath(), discovered.getLogoutPath());
    assertSameEndpoint(should, expected, expected.getJwkPath(), discovered.getJwkPath());
  }

  private static void assertSameEndpoint(TestContext should, OAuth2Options expected, String expectedPath, String discoveredUrl) {
    if (discoveredUrl == null) {
      // not advertised by the provider, nothing to compare against
      return;
    }
    should.assertNotNull(expectedPath, "provider advertises " + discoveredUrl + " but the shortcut does not configure it");
    String expectedUrl = expectedPath.startsWith("http") ? expectedPath : expected.getSite() + expectedPath;
    should.assertEquals(expectedUrl, discoveredUrl);
  }

  @Test
  public void testTwitch(TestContext should) {
    final Async test = should.async();

    final OAuth2Options expected = ((OAuth2AuthProviderImpl) TwitchAuth.create(rule.vertx(), "client-id", "client-secret")).getConfig();

    TwitchAuth.discover(rule.vertx(), new OAuth2Options().setClientId("client-id").setClientSecret("client-secret"))
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {
        OAuth2Options discovered = ((OAuth2AuthProviderImpl) oauth2).getConfig();
        assertSameEndpoints(should, expected, discovered);
        // Twitch advertises these endpoints, make sure they were really compared
        should.assertNotNull(discovered.getAuthorizationPath());
        should.assertNotNull(discovered.getTokenPath());
        should.assertNotNull(discovered.getUserInfoPath());
        should.assertNotNull(discovered.getJwkPath());
        should.assertEquals("https://id.twitch.tv/oauth2", discovered.getJWTOptions().getIssuer());
        // discover() must keep the Twitch specific client authentication method
        should.assertFalse(discovered.isUseBasicAuthorization());
        test.complete();
      });
  }

  @Test
  public void testOktaOrgAuthorizationServer(TestContext should) {
    final Async test = should.async();

    // okta.okta.com is Okta's own public org, its discovery documents are reachable without credentials
    final OAuth2Options expected = ((OAuth2AuthProviderImpl) OktaAuth.create(rule.vertx(), "client-id", "client-secret", "okta.okta.com")).getConfig();

    OktaAuth.discover(rule.vertx(), new OAuth2Options()
        .setSite("https://okta.okta.com")
        .setClientId("client-id")
        .setClientSecret("client-secret"))
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {
        OAuth2Options discovered = ((OAuth2AuthProviderImpl) oauth2).getConfig();
        assertSameEndpoints(should, expected, discovered);
        // Okta advertises all the endpoints configured by the shortcut, make sure they were really compared
        should.assertNotNull(discovered.getAuthorizationPath());
        should.assertNotNull(discovered.getTokenPath());
        should.assertNotNull(discovered.getUserInfoPath());
        should.assertNotNull(discovered.getRevocationPath());
        should.assertNotNull(discovered.getIntrospectionPath());
        should.assertNotNull(discovered.getLogoutPath());
        should.assertNotNull(discovered.getJwkPath());
        should.assertEquals("https://okta.okta.com", discovered.getJWTOptions().getIssuer());
        test.complete();
      });
  }

  @Test
  public void testOktaCustomAuthorizationServer(TestContext should) {
    final Async test = should.async();

    final OAuth2Options expected = ((OAuth2AuthProviderImpl) OktaAuth.create(rule.vertx(), "client-id", "client-secret", "okta.okta.com", "default")).getConfig();

    OktaAuth.discover(rule.vertx(), new OAuth2Options()
        .setSite("https://okta.okta.com/oauth2/default")
        .setClientId("client-id")
        .setClientSecret("client-secret"))
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {
        OAuth2Options discovered = ((OAuth2AuthProviderImpl) oauth2).getConfig();
        assertSameEndpoints(should, expected, discovered);
        should.assertNotNull(discovered.getAuthorizationPath());
        should.assertNotNull(discovered.getTokenPath());
        should.assertNotNull(discovered.getUserInfoPath());
        should.assertNotNull(discovered.getRevocationPath());
        should.assertNotNull(discovered.getIntrospectionPath());
        should.assertNotNull(discovered.getLogoutPath());
        should.assertNotNull(discovered.getJwkPath());
        should.assertEquals("https://okta.okta.com/oauth2/default", discovered.getJWTOptions().getIssuer());
        test.complete();
      });
  }

}
