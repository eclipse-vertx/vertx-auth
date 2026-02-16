package io.vertx.tests;

import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockserver.client.MockServerClient;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpTemplate;
import org.mockserver.model.MediaType;
import org.testcontainers.containers.MockServerContainer;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@RunWith(VertxUnitRunner.class)
public class OpenIDCDiscoveryTest {
  private static final DockerImageName MOCKSERVER_IMAGE = DockerImageName
    .parse("mockserver/mockserver")
    .withTag("mockserver-" + MockServerClient.class.getPackage().getImplementationVersion());

  @ClassRule
  public static final MockServerContainer mockServer = new MockServerContainer(MOCKSERVER_IMAGE);
  public static MockServerClient mockServerClient;

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @BeforeClass
  public static void setup() {
    mockServerClient = new MockServerClient(mockServer.getHost(), mockServer.getServerPort());
  }

  @AfterClass
  public static void teardown() {
    // This will also stop MockServer
    mockServerClient.stop();
  }

  @Before
  public void resetMockServer() {
    mockServerClient.reset();
  }

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

  @Test
  public void testConfiguredFlowTypes(TestContext should) {
    final Async test = should.async(3);

    // Setup expectations for mockserver
    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(fakeAuthServerConfigurationTemplate());

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/jwks")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(
        response()
          .withContentType(MediaType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
          .withBody("{\"keys\": []}")
      );

    // Configured grant types should be retained, as the server doesn't send any
    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
          .addSupportedGrantType(OAuth2FlowType.AUTH_CODE.getGrantType()))
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        should.assertEquals(
          new HashSet<>(options.getSupportedGrantTypes()),
          Set.of(OAuth2FlowType.AUTH_CODE.getGrantType())
        );

        test.countDown();
      })
      .onFailure(should::fail);

    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          // This one should work without a client ID, as it is not required when only the implicit flow is supported
          //.setClientId("test-client")
          .addSupportedGrantType(OAuth2FlowType.IMPLICIT.getGrantType()))
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        should.assertEquals(
          new HashSet<>(options.getSupportedGrantTypes()),
          Set.of(OAuth2FlowType.IMPLICIT.getGrantType())
        );

        test.countDown();
      })
      .onFailure(should::fail);

    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
          .addSupportedGrantType(OAuth2FlowType.AUTH_JWT.getGrantType())
          .addSupportedGrantType(OAuth2FlowType.AUTH_CODE.getGrantType())
          .addSupportedGrantType(OAuth2FlowType.IMPLICIT.getGrantType())
      )
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        should.assertEquals(
          new HashSet<>(options.getSupportedGrantTypes()),
          Set.of(
            OAuth2FlowType.IMPLICIT.getGrantType(),
            OAuth2FlowType.AUTH_JWT.getGrantType(),
            OAuth2FlowType.AUTH_CODE.getGrantType()
          )
        );

        test.countDown();
      })
      .onFailure(should::fail);
  }

  @Test
  public void testIntersectFlowTypes(TestContext should) {
    final Async test = should.async(2);

    // Setup expectations for mockserver
    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET"),
        Times.exactly(1)
      )
      .respond(fakeAuthServerConfigurationTemplate(OAuth2FlowType.AUTH_CODE, OAuth2FlowType.IMPLICIT));

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET"),
        Times.exactly(1)
      )
      .respond(fakeAuthServerConfigurationTemplate(OAuth2FlowType.IMPLICIT, OAuth2FlowType.PASSWORD, OAuth2FlowType.AUTH_CODE));

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/jwks")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(
        response()
          .withContentType(MediaType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
          .withBody("{\"keys\": []}")
      );

    // Configured grant types should be overridden, as the server sends some
    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          // This one should work without a client ID, as it is not required when only the implicit flow is supported
          //.setClientId("test-client")
          .addSupportedGrantType(OAuth2FlowType.IMPLICIT.getGrantType()))
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        // Server sends authorization_code, implicit, so the intersection is only implicit
        should.assertEquals(
          new HashSet<>(options.getSupportedGrantTypes()),
          Set.of(OAuth2FlowType.IMPLICIT.getGrantType())
        );

        test.countDown();

        // Need to serialize requests this time to make the assertions reproducible
        OpenIDConnectAuth.discover(
            rule.vertx(),
            new OAuth2Options()
              .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
              .setTenant("test")
              .setClientId("test-client")
              .addSupportedGrantType(OAuth2FlowType.AUTH_CODE.getGrantType())
              .addSupportedGrantType(OAuth2FlowType.IMPLICIT.getGrantType()))
          .onSuccess(result2 -> {
            var options2 = ((OAuth2AuthProviderImpl) result2).getConfig();

            // Server sends authorization_code, implicit, password, so the intersection is implicit, authorization_code
            should.assertEquals(
              new HashSet<>(options2.getSupportedGrantTypes()),
              Set.of(
                OAuth2FlowType.IMPLICIT.getGrantType(),
                OAuth2FlowType.AUTH_CODE.getGrantType()
              )
            );

            test.countDown();
          })
          .onFailure(should::fail);
      })
      .onFailure(should::fail);
  }

  @Test
  public void testServerSupportedFlowTypes(TestContext should) {
    final Async test = should.async(2);

    // Setup expectations for mockserver
    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET"),
        Times.exactly(1)
      )
      .respond(fakeAuthServerConfigurationTemplate(OAuth2FlowType.AUTH_CODE, OAuth2FlowType.IMPLICIT));

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET"),
        Times.exactly(1)
      )
      .respond(fakeAuthServerConfigurationTemplate(OAuth2FlowType.IMPLICIT, OAuth2FlowType.PASSWORD, OAuth2FlowType.AUTH_CODE));

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/jwks")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(
        response()
          .withContentType(MediaType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
          .withBody("{\"keys\": []}")
      );

    // Configured grant types should be overridden, as the server sends some
    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
      )
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        // Server sends authorization_code, implicit
        should.assertEquals(
          new HashSet<>(options.getSupportedGrantTypes()),
          Set.of(OAuth2FlowType.AUTH_CODE.getGrantType(), OAuth2FlowType.IMPLICIT.getGrantType())
        );

        test.countDown();

        // Need to serialize requests this time to make the assertions reproducible
        OpenIDConnectAuth.discover(
            rule.vertx(),
            new OAuth2Options()
              .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
              .setTenant("test")
              .setClientId("test-client")
          )
          .onSuccess(result2 -> {
            var options2 = ((OAuth2AuthProviderImpl) result2).getConfig();

            // Server sends authorization_code, implicit, password
            should.assertEquals(
              new HashSet<>(options2.getSupportedGrantTypes()),
              Set.of(
                OAuth2FlowType.IMPLICIT.getGrantType(),
                OAuth2FlowType.PASSWORD.getGrantType(),
                OAuth2FlowType.AUTH_CODE.getGrantType()
              )
            );

            test.countDown();
          })
          .onFailure(should::fail);
      })
      .onFailure(should::fail);
  }

  @Test
  public void testDefaultFlowTypes(TestContext should) {
    final Async test = should.async(2);

    // Setup expectations for mockserver
    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
        )
      .respond(fakeAuthServerConfigurationTemplate());

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/jwks")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(
        response()
          .withContentType(MediaType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
          .withBody("{\"keys\": []}")
      );

    // Configured grant types should be overridden, as the server sends some
    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
      )
      .onSuccess(result -> {
        var options = ((OAuth2AuthProviderImpl) result).getConfig();

        // Server sends nothing, nothing is configured -> fall back to default
        should.assertNull(options.getSupportedGrantTypes());

        test.countDown();
      })
      .onFailure(should::fail);

    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
      )
      .onSuccess(result2 -> {
        var options2 = ((OAuth2AuthProviderImpl) result2).getConfig();

        // Server sends nothing, nothing is configured -> fall back to default
        should.assertNull(options2.getSupportedGrantTypes());

        test.countDown();
      })
      .onFailure(should::fail);
  }

  @Test
  public void testNoSupportedFlowTypes(TestContext should) {
    final Async test = should.async(2);

    // Setup expectations for mockserver
    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/.well-known/openid-configuration")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(fakeAuthServerConfigurationTemplate(OAuth2FlowType.AUTH_CODE, OAuth2FlowType.IMPLICIT));

    mockServerClient
      .when(
        request()
          .withPath("/fake-auth-server/{tenant}/jwks")
          .withPathParameter("tenant", "[a-z][a-zA-Z0-9]*")
          .withMethod("GET")
      )
      .respond(
        response()
          .withContentType(MediaType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
          .withBody("{\"keys\": []}")
      );

    // Configured grant types should be overridden, as the server sends some
    OpenIDConnectAuth.discover(
        rule.vertx(),
        new OAuth2Options()
          .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
          .setTenant("test")
          .setClientId("test-client")
          .addSupportedGrantType(OAuth2FlowType.PASSWORD.getGrantType())
      )
      .onSuccess(result -> should.fail("Discovery should fail"))
      .onFailure(err -> {
        should.assertEquals(
          "No supported grant types with this authorization provider. Supported: [authorization_code, implicit]. Configured: [password]",
          err.getMessage()
        );

        test.countDown();

        // Need to serialize requests this time to make the assertions reproducible
        OpenIDConnectAuth.discover(
            rule.vertx(),
            new OAuth2Options()
              .setSite(mockServer.getEndpoint() + "/fake-auth-server/{tenant}")
              .setTenant("test")
              .setClientId("test-client")
              .addSupportedGrantType(OAuth2FlowType.CLIENT.getGrantType())
              .addSupportedGrantType(OAuth2FlowType.PASSWORD.getGrantType())
              .addSupportedGrantType(OAuth2FlowType.AUTH_JWT.getGrantType())
          )
          .onSuccess(result -> should.fail("Discovery should fail"))
          .onFailure(err2 -> {
            should.assertEquals(
              "No supported grant types with this authorization provider. Supported: [authorization_code, implicit]. Configured: [client_credentials, password, urn:ietf:params:oauth:grant-type:jwt-bearer]",
              err2.getMessage()
            );

            test.countDown();
          });
      });
  }

  private static HttpTemplate fakeAuthServerConfigurationTemplate(OAuth2FlowType... supportedGrantTypes) {
    var base = mockServer.getEndpoint() + "/fake-auth-server/{{request.pathParameters.tenant.0}}";
    var body = "{" +
      "\\\"issuer\\\": \\\"" + base + "\\\"," +
      "\\\"authorization_endpoint\\\": \\\"" + base + "/auth\\\"," +
      "\\\"token_endpoint\\\": \\\"" + base + "/token\\\"," +
      "\\\"end_session_endpoint\\\": \\\"" + base + "/logout\\\"," +
      "\\\"revocation_endpoint\\\": \\\"" + base + "/revoke\\\"," +
      "\\\"userinfo_endpoint\\\": \\\"" + base + "/userinfo\\\"," +
      "\\\"introspection_endpoint\\\": \\\"" + base + "/introspect\\\",";

    if (supportedGrantTypes.length > 0) {
      body += "\\\"grant_types_supported\\\": " +
        Stream.of(supportedGrantTypes)
          .map(OAuth2FlowType::getGrantType)
          .map(grantType -> "\\\"" + grantType + "\\\"")
          .collect(Collectors.joining(", ", "[", "]")) +
        ",";
    }

    body += "\\\"jwks_uri\\\": \\\"" + base + "/jwks\\\"";
    body += "}";

    var template =
      "{\n" +
        "  \"statusCode\": 200,\n" +
        "  \"headers\": {\"Content-Type\": \"application/json; charset=utf-8\"},\n" +
        "  \"body\": \"" + body + "\"\n" +
        "}";

    return HttpTemplate.template(HttpTemplate.TemplateType.MUSTACHE, template);
  }
}
