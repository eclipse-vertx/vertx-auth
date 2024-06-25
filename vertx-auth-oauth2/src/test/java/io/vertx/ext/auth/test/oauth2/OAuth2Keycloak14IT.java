package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.jwt.authorization.MicroProfileAuthorization;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.Oauth2Credentials;
import io.vertx.ext.auth.oauth2.authorization.KeycloakAuthorization;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
@Parameterized.UseParametersRunnerFactory(VertxUnitRunnerWithParametersFactory.class)
public class OAuth2Keycloak14IT {

  @ClassRule
  public static GenericContainer<?> container = new GenericContainer<>("quay.io/keycloak/keycloak:14.0.0")
    .withEnv("KEYCLOAK_USER", "admin")
    .withEnv("KEYCLOAK_PASSWORD", "secret")
    .withEnv("DB_VENDOR", "H2")
    .withExposedPorts(8080, 8443)
    .withClasspathResourceMapping("vertx-it-realm.json", "/tmp/fixtures.json", BindMode.READ_ONLY)
    .withCommand("-b", "0.0.0.0", "-Dkeycloak.migration.action=import", "-Dkeycloak.migration.provider=singleFile", "-Dkeycloak.migration.file=/tmp/fixtures.json", "-Dkeycloak.migration.strategy=OVERWRITE_EXISTING")
    .waitingFor(Wait.forLogMessage(".*Keycloak.*started.*", 1));


  @Parameterized.Parameters
  public static List<String> sites() {
    return Arrays.asList("http", "https");
  }

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private final String proto;
  private String site;

  public OAuth2Keycloak14IT(String proto) {
    this.proto = proto;
  }

  @Before
  public void setUp() {
    switch (proto) {
      case "http":
        site = proto + "://" + container.getContainerIpAddress() + ":" + container.getMappedPort(8080);
        break;
      case "https":
        site = proto + "://" + container.getContainerIpAddress() + ":" + container.getMappedPort(8443);
        break;
      default:
        throw new IllegalArgumentException("Invalid proto: " + proto);
    }
  }

  @Test
  public void discoverPublicOpenId(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("public")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", "account", Arrays.asList("openid"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            KeycloakAuthorization.create()
              .getAuthorizations(alice)
              .onFailure(should::fail)
              .onSuccess(v -> {
                // default from oidc
                should.assertTrue(RoleBasedAuthorization.create("offline_access").match(alice));
                // default from the realm
                should.assertTrue(RoleBasedAuthorization.create("default-roles-vertx-it").match(alice));
                // resource based role always present by default on keycloak
                should.assertTrue(RoleBasedAuthorization.create("view-profile").setResource("account").match(alice));

                loginAs(oauth2, should, "bob", "account", null)
                  .onSuccess(bob -> {
                    test.complete();
                  });
              });
          });
      });
  }

  @Test
  public void discoverPublic(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("public")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", "account", null)
          .onSuccess(alice -> {
            // we should not receive a idToken
            should.assertNull(alice.attributes().getJsonObject("idToken"));

            KeycloakAuthorization.create()
              .getAuthorizations(alice)
              .onFailure(should::fail)
              .onSuccess(v -> {
                // default from oidc
                should.assertTrue(RoleBasedAuthorization.create("offline_access").match(alice));
                // default from the realm
                should.assertTrue(RoleBasedAuthorization.create("default-roles-vertx-it").match(alice));
                // resource based role always present by default on keycloak
                should.assertTrue(RoleBasedAuthorization.create("view-profile").setResource("account").match(alice));

                loginAs(oauth2, should, "bob", "account", null)
                  .onSuccess(bob -> {
                    test.complete();
                  });
              });
          });
      });
  }

  @Test
  public void discoverConfidential(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("confidential")
      .setClientSecret("51321e70-b1f3-45bf-aec2-d6bfbb9327e3")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", "account", Arrays.asList("openid"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            KeycloakAuthorization.create()
              .getAuthorizations(alice)
              .onFailure(should::fail)
              .onSuccess(v -> {
                // default from oidc
                should.assertTrue(RoleBasedAuthorization.create("offline_access").match(alice));
                // default from the realm
                should.assertTrue(RoleBasedAuthorization.create("default-roles-vertx-it").match(alice));
                // resource based role always present by default on keycloak
                should.assertTrue(RoleBasedAuthorization.create("view-profile").setResource("account").match(alice));

                loginAs(oauth2, should, "bob", "account", null)
                  .onSuccess(bob -> {
                    test.complete();
                  });
              });
          });
      });
  }

  @Test
  public void discoverOwnAudience(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("own-audience")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}");

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", options.getClientId(), Arrays.asList("openid"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            loginAs(oauth2, should, "bob", options.getClientId(), null)
              .onSuccess(bob -> {
                test.complete();
              });
          });
      });
  }

  @Test
  public void discoverMultipleAudienceDefault(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("multiple-audience")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}");

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", Arrays.asList(options.getClientId(), "account"), Arrays.asList("openid"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            loginAs(oauth2, should, "bob", Arrays.asList(options.getClientId(), "account"), null)
              .onSuccess(bob -> {
                test.complete();
              });
          });
      });
  }

  @Test
  public void discoverMultipleAudienceWithAudiencesInConfig(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("multiple-audience")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(new JWTOptions()
        .addAudience("multiple-audience")
        .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", options.getJWTOptions().getAudience(), Arrays.asList("openid"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            loginAs(oauth2, should, "bob", options.getJWTOptions().getAudience(), null)
              .onSuccess(bob -> {
                test.complete();
              });
          });
      });
  }

  @Test
  public void discoverPublicMicroprofile(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("public")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}")
      .setJWTOptions(
        new JWTOptions()
          .addAudience("account"));

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        loginAs(oauth2, should, "alice", "account", Arrays.asList("openid", "microprofile-jwt"))
          .onSuccess(alice -> {

            should.assertNotNull(alice.attributes().getJsonObject("idToken"));
            should.assertEquals(options.getClientId(), alice.attributes().getJsonObject("idToken").getString("aud"));

            MicroProfileAuthorization.create()
              .getAuthorizations(alice)
              .onFailure(should::fail)
              .onSuccess(v -> {
                // default from oidc
                should.assertTrue(RoleBasedAuthorization.create("offline_access").match(alice));
                // default from the realm
                should.assertTrue(RoleBasedAuthorization.create("default-roles-vertx-it").match(alice));

                loginAs(oauth2, should, "bob", "account", null)
                  .onSuccess(bob -> {
                    test.complete();
                  });
              });
          });
      });
  }

  @Test
  public void discoverGetTokenFromFrontEndPerformAuthWithBackend(TestContext should) {
    final Async test = should.async();

    // in this test we get a token from client "frontend", the token should contain an audience "backend" so it is not
    // consumable from "this" app directly. The token should be seen as an opaque token.

    // then we use that token to authenticate on client "backend" which should be accepted as the audience is correct.

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("frontend")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}");

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {

        oauth2
          .authenticate(new Oauth2Credentials().setUsername("alice").setPassword("password").addScope("backend"))
          .onFailure(should::fail)
          .onSuccess(alice -> {
            should.assertNotNull(alice);
            // the audience isn't valid so the token is considered opaque
            should.assertNull(alice.attributes().getJsonObject("accessToken"));

            // step #2 use the token acquired by the frontend and perform authn to "backend"
            OAuth2Options options2 = new OAuth2Options()
              .setClientId("backend")
              .setTenant("vertx-it")
              .setSite(site + "/auth/realms/{tenant}");

            options2.getHttpClientOptions().setTrustAll(true);

            KeycloakAuth.discover(rule.vertx(), options2)
              .onFailure(should::fail)
              .onSuccess(oAuth2 -> {

                // perform auth using a token, this is a bearer client, so it assumes tokens have been issued elsewhere
                oAuth2
                  .authenticate(new TokenCredentials(alice.principal().getString("access_token")))
                  .onFailure(should::fail)
                  .onSuccess(backendAlice -> {
                    should.assertNotNull(backendAlice);
                    // the audience is valid so the token is a JWT
                    should.assertNotNull(backendAlice.attributes().getJsonObject("accessToken"));
                    // and the right audience is present
                    should.assertTrue(backendAlice.attributes().getJsonObject("accessToken").getJsonArray("aud").contains("backend"));

                    test.complete();
                  });
              });
          });
      });
  }

  @Test
  public void discoverGetTokenFromFrontEndPerformAuthWithBorkendWillFail(TestContext should) {
    final Async test = should.async();

    // in this test we get a token from client "frontend", the token should contain an audience "backend" so it is not
    // consumable from "this" app directly. The token should be seen as an opaque token.

    // then we use that token to authenticate on client "borkend" which should fail as we have a "typpo" client and the
    // audience will not match.

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientId("frontend")
      .setTenant("vertx-it")
      .setSite(site + "/auth/realms/{tenant}");

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(rule.vertx(), options)
      .onFailure(should::fail)
      .onSuccess(oauth2 -> {
        oauth2
          .authenticate(
            new Oauth2Credentials()
              .setUsername("alice")
              .setPassword("password")
              // this is a client scope that will add the "backend" audience to the token
              .addScope("backend"))
          .onFailure(should::fail)
          .onSuccess(alice -> {
            should.assertNotNull(alice);
            // the audience isn't valid so the token is considered opaque
            should.assertNull(alice.attributes().getJsonObject("accessToken"));

            // step #2 use the token acquired by the frontend and perform authn to "backend"
            OAuth2Options options2 = new OAuth2Options()
              .setClientId("borkend")
              .setTenant("vertx-it")
              .setSite(site + "/auth/realms/{tenant}");

            options2.getHttpClientOptions().setTrustAll(true);

            KeycloakAuth.discover(rule.vertx(), options2)
              .onFailure(should::fail)
              .onSuccess(oAuth2 -> {

                // perform auth using a token, this is a bearer client, so it assumes tokens have been issued elsewhere
                oAuth2
                  .authenticate(new TokenCredentials(alice.principal().getString("access_token")))
                  .onFailure(err -> test.complete())
                  .onSuccess(backendAlice -> should.fail("We are on the wrong audience for a bearer client"));
              });
          });
      });
  }

  private Future<User> loginAs(OAuth2Auth oauth2, TestContext should, String username, String audience, List<String> scopes) {
    final Promise<User> promise = Promise.promise();

    oauth2
      .authenticate(new Oauth2Credentials().setUsername(username).setPassword("password").setScopes(scopes))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        should.assertNotNull(user.attributes().getJsonObject("accessToken"));
        should.assertEquals(audience, user.attributes().getJsonObject("accessToken").getString("aud"));
        promise.complete(user);
      });

    return promise.future();
  }

  private Future<User> loginAs(OAuth2Auth oauth2, TestContext should, String username, List<String> audience, List<String> scopes) {
    final Promise<User> promise = Promise.promise();

    oauth2
      .authenticate(new Oauth2Credentials().setUsername(username).setPassword("password").setScopes(scopes))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        should.assertNotNull(user.attributes().getJsonObject("accessToken"));
        should.assertEquals(audience, user.attributes().getJsonObject("accessToken").getJsonArray("aud").getList());
        promise.complete(user);
      });

    return promise.future();
  }
}
