package io.vertx.tests;

import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.Oauth2Credentials;
import io.vertx.ext.auth.oauth2.authorization.KeycloakAuthorization;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
@Parameterized.UseParametersRunnerFactory(VertxUnitRunnerWithParametersFactory.class)
public class OAuth2KeycloakIT {

//  @ClassRule
  public static GenericContainer<?> container = null/*new GenericContainer<>("quay.io/keycloak/keycloak:6.0.0")
    .withEnv("KEYCLOAK_USER", "user")
    .withEnv("KEYCLOAK_PASSWORD", "password")
    .withEnv("DB_VENDOR", "H2")
    .withExposedPorts(8080, 8443)
    .withClasspathResourceMapping("vertx-test-realm.json", "/tmp/vertx-test-realm.json", BindMode.READ_ONLY)
    .withCommand("-b", "0.0.0.0", "-Dkeycloak.migration.action=import", "-Dkeycloak.migration.provider=singleFile", "-Dkeycloak.migration.file=/tmp/vertx-test-realm.json", "-Dkeycloak.migration.strategy=OVERWRITE_EXISTING")
    .waitingFor(Wait.forLogMessage(".*Keycloak.*started.*", 1))*/;


  @Parameterized.Parameters
  public static List<String> sites() {
    return Arrays.asList("http", "https");
  }

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private final String proto;
  private OAuth2Auth keycloak;
  private String site;

  public OAuth2KeycloakIT(String proto) {
    this.proto = proto;
  }

  @Before
  public void setUp(TestContext should) {
    final Async test = should.async();

    switch (proto) {
      case "http":
        site = proto + "://" + container.getHost() + ":" + container.getMappedPort(8080);
        break;
      case "https":
        site = proto + "://" + container.getHost() + ":" + container.getMappedPort(8443);
        break;
      default:
        throw new IllegalArgumentException("Invalid proto: " + proto);
    }

    OAuth2Options options = new OAuth2Options()
      .setClientId("confidential-client")
      .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e")
      .setTenant("vertx-test")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(
        rule.vertx(),
        options)
      .onComplete(discover -> {
        should.assertTrue(discover.succeeded());
        keycloak = discover.result();
        test.complete();
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldLoginWithUsernamePassword(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());
        should.assertNotNull(authn.result().attributes().getJsonObject("accessToken"));
        test.complete();
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldLoginWithUsernamePasswordAndGetIdToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.PASSWORD).setUsername("test-user").setPassword("tiger").addScope("openid"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());
        should.assertNotNull(authn.result().attributes().getJsonObject("accessToken"));
        should.assertNotNull(authn.result().attributes().getJsonObject("idToken"));
        test.complete();
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldLoginWithAccessToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        keycloak.authenticate(new TokenCredentials(token.principal().getString("access_token")))
          .onComplete(authn2 -> {
            should.assertTrue(authn2.succeeded());
            should.assertNotNull(authn2.result());
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldFailLoginWithInvalidToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new TokenCredentials("aaaaaaaaaaaaaaaaaa"))
      .onComplete(authn2 -> {
        should.assertTrue(authn2.failed());
        should.assertNotNull(authn2.cause());
        test.complete();
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldIntrospectAccessTokenInactive(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        OAuth2Options options = new OAuth2Options()
          .setClientId("confidential-client")
          .setTenant("vertx-test")
          .setSite(site + "/auth/realms/{realm}")
          .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e");

        options.getHttpClientOptions().setTrustAll(true);

        // get a auth handler for the confidential client
        KeycloakAuth.discover(
            rule.vertx(),
            options)
          .onComplete(discover -> {
            should.assertTrue(discover.succeeded());
            OAuth2Auth confidential = discover.result();
            try {
              Thread.sleep(5000L);
            } catch (InterruptedException e) {
            }
            confidential.authenticate(new TokenCredentials(token.principal().getString("access_token")))
              .onComplete(introspect -> {
                should.assertTrue(introspect.failed());
                should.assertEquals("Inactive Token", introspect.cause().getMessage());
                test.complete();
              });
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldIntrospectAccessToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        OAuth2Options options = new OAuth2Options()
          .setClientId("confidential-client")
          .setTenant("vertx-test")
          .setSite(site + "/auth/realms/{realm}")
          .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e");

        options.getHttpClientOptions().setTrustAll(true);

        // get a auth handler for the confidential client
        KeycloakAuth.discover(
            rule.vertx(),
            options)
          .onComplete(discover -> {
            should.assertTrue(discover.succeeded());
            OAuth2Auth confidential = discover.result();
            confidential.authenticate(new TokenCredentials(token.principal().getString("access_token")))
              .onComplete(introspect -> {
                should.assertTrue(introspect.succeeded());
                test.complete();
              });
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldGetPermissionsFromToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        // assert that the user has the following roles:
        final List<String> roles = Arrays.asList(
          // scopes
          "profile", "email",
          // top level roles (resource)
          "realm:offline_access", "realm:user",
          // application level roles
          "confidential-client:test",
          "account:manage-account",
          "account:manage-account-links",
          "account:view-profile"
        );

        ScopeAuthorization.create(" ").getAuthorizations(token)
          .onComplete(authz1 -> {
            should.assertTrue(authz1.succeeded());
            should.assertTrue(PermissionBasedAuthorization.create("profile").match(token));
            should.assertTrue(PermissionBasedAuthorization.create("email").match(token));

            KeycloakAuthorization.create().getAuthorizations(token)
              .onComplete(authz2 -> {
                should.assertTrue(authz2.succeeded());
                should.assertTrue(RoleBasedAuthorization.create("offline_access").match(token));
                should.assertTrue(RoleBasedAuthorization.create("user").match(token));
                should.assertTrue(RoleBasedAuthorization.create("test").setResource("confidential-client").match(token));
                should.assertTrue(RoleBasedAuthorization.create("manage-account").setResource("account").match(token));
                should.assertTrue(RoleBasedAuthorization.create("manage-account-links").setResource("account").match(token));
                should.assertTrue(RoleBasedAuthorization.create("view-profile").setResource("account").match(token));
                test.complete();
              });
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldGetPermissionsFromTokenButPermissionIsNotAllowed(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        KeycloakAuthorization.create().getAuthorizations(token)
          .onComplete(authz -> {
            should.assertTrue(authz.succeeded());
            should.assertFalse(PermissionBasedAuthorization.create("sudo").match(token));
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldLoadTheUserInfo(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        keycloak.userInfo(token)
          .onComplete(userinfo -> {
            should.assertTrue(userinfo.succeeded());
            should.assertNotNull(userinfo.result());

            should.assertEquals("test-user", userinfo.result().getString("preferred_username"));
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldRefreshAToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
      .onComplete(authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        final String origToken = token.principal().getString("access_token");

        keycloak.refresh(token)
          .onComplete(refresh -> {
            should.assertTrue(refresh.succeeded());

            should.assertNotEquals(origToken, refresh.result().principal().getString("access_token"));
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldReloadJWK(TestContext should) {
    final Async test = should.async();

    keycloak.jWKSet()
      .onComplete(load -> {
        should.assertTrue(load.succeeded());

        keycloak.authenticate(new UsernamePasswordCredentials("test-user", "tiger"))
          .onComplete(authn -> {
            should.assertTrue(authn.succeeded());
            should.assertNotNull(authn.result());

            // generate a access token from the user
            User token = authn.result();

            should.assertNotNull(token.attributes().getJsonObject("accessToken"));
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void shouldDiscoverGrant(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setClientId("confidential-client")
      .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e")
      .setTenant("vertx-test")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(
        rule.vertx(),
        options)
      .onComplete(discover -> {
        should.assertTrue(discover.succeeded());
        OAuth2Auth keycloak = discover.result();
        keycloak.authenticate(new Oauth2Credentials().setUsername("test-user").setPassword("tiger").setFlow(OAuth2FlowType.PASSWORD))
          .onComplete(authn -> {
            should.assertTrue(authn.succeeded());
            test.complete();
          });
      });
  }

  @Ignore("Failed to get Docker client for quay.io/keycloak/keycloak:6.0.0")
  @Test
  public void unsupportedGrant(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setClientId("confidential-client")
      .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e")
      .setTenant("vertx-test")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(
        rule.vertx(),
        options)
      .onComplete(discover -> {
        should.assertTrue(discover.succeeded());
        OAuth2Auth keycloak = discover.result();
        keycloak.authenticate(new Oauth2Credentials().setAssertion("xyz").setFlow(OAuth2FlowType.AAD_OBO))
          .onComplete(authn -> {
            should.assertTrue(authn.failed());
            should.assertEquals("Provided flow is not supported by provider", authn.cause().getMessage());
            test.complete();
          });
      });
  }
}
