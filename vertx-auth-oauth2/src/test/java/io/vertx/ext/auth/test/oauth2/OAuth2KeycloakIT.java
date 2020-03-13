package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.authorization.KeycloakAuthorization;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunnerWithParametersFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
@Parameterized.UseParametersRunnerFactory(VertxUnitRunnerWithParametersFactory.class)
public class OAuth2KeycloakIT {

  @Parameterized.Parameters
  public static List<String> sites() {
    return Arrays.asList("http://localhost:8888", "https://localhost:9443");
  }

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private OAuth2Auth keycloak;
  private final String site;

  public OAuth2KeycloakIT(String site) {
    this.site = site;
  }

  @Before
  public void setUp(TestContext should) {
    final Async test = should.async();

    OAuth2Options options = new OAuth2Options()
      .setFlow(OAuth2FlowType.PASSWORD)
      .setClientID("public-client")
      .setTenant("vertx-test")
      .setSite(site + "/auth/realms/{tenant}");

    options.getHttpClientOptions().setTrustAll(true);

    KeycloakAuth.discover(
      rule.vertx(),
      options,
      discover -> {
        should.assertTrue(discover.succeeded());
        keycloak = discover.result();
        test.complete();
      });
  }

  @Test
  public void shouldLoginWithUsernamePassword(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());
      test.complete();
    });
  }

  @Test
  public void shouldLoginWithAccessToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      User token = authn.result();

      keycloak.authenticate(new JsonObject().put("access_token", token.principal().getString("access_token")).put("token_type", "Bearer"), authn2 -> {
        should.assertTrue(authn2.succeeded());
        should.assertNotNull(authn2.result());
        test.complete();
      });
    });
  }

  @Test
  public void shouldFailLoginWithInvalidToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("access_token", "aaaaaaaaaaaaaaaaaa").put("token_type", "Bearer"), authn2 -> {
      should.assertTrue(authn2.failed());
      should.assertNotNull(authn2.cause());
      test.complete();
    });
  }

  @Test
  public void shouldIntrospectAccessToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      User token = authn.result();

      OAuth2Options options = new OAuth2Options()
        .setFlow(OAuth2FlowType.PASSWORD)
        .setClientID("confidential-client")
        .setTenant("vertx-test")
        .setSite(site + "/auth/realms/{realm}")
        .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e");

      options.getHttpClientOptions().setTrustAll(true);

      // get a auth handler for the confidential client
      KeycloakAuth.discover(
        rule.vertx(),
        options,
        discover -> {
          should.assertTrue(discover.succeeded());
          OAuth2Auth confidential = discover.result();

          confidential.authenticate(token.principal(), introspect -> {
            should.assertTrue(introspect.succeeded());
            test.complete();
          });
        });
    });
  }

  @Test
  public void shouldGetPermissionsFromToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
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

      ScopeAuthorization.create(" ").getAuthorizations(token, authz1 -> {
        should.assertTrue(authz1.succeeded());
        should.assertTrue(PermissionBasedAuthorization.create("profile").match(token));
        should.assertTrue(PermissionBasedAuthorization.create("email").match(token));

        KeycloakAuthorization.create().getAuthorizations(token, authz2 -> {
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

  @Test
  public void shouldGetPermissionsFromTokenButPermissionIsNotAllowed(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      User token = authn.result();

      KeycloakAuthorization.create().getAuthorizations(token, authz -> {
        should.assertTrue(authz.succeeded());
        should.assertFalse(PermissionBasedAuthorization.create("sudo").match(token));
        test.complete();
      });
    });
  }

  @Test
  public void shouldLoadTheUserInfo(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      User token = authn.result();

      keycloak.userInfo(token, userinfo -> {
        should.assertTrue(userinfo.succeeded());
        should.assertNotNull(userinfo.result());

        should.assertEquals("test-user", userinfo.result().getString("preferred_username"));
        test.complete();
      });
    });
  }

  @Test
  public void shouldRefreshAToken(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      User token = authn.result();

      final String origToken = token.principal().getString("access_token");

      keycloak.refresh(token, refresh -> {
        should.assertTrue(refresh.succeeded());

        should.assertNotEquals(origToken, refresh.result().principal().getString("access_token"));
        test.complete();
      });
    });
  }

  @Test
  public void shouldReloadJWK(TestContext should) {
    final Async test = should.async();

    keycloak.jWKSet(load -> {
      should.assertTrue(load.succeeded());

      keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        User token = authn.result();

        should.assertNotNull(token.principal().getJsonObject("accessToken"));
        test.complete();
      });
    });
  }
}
