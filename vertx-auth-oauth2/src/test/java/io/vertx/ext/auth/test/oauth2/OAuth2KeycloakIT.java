package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(VertxUnitRunner.class)
public class OAuth2KeycloakIT {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private OAuth2Auth keycloak;

  @Before
  public void setUp(TestContext should) {
    final Async test = should.async();

    KeycloakAuth.discover(
      rule.vertx(),
      new OAuth2ClientOptions()
        .setFlow(OAuth2FlowType.PASSWORD)
        .setSite("http://127.0.0.1:8888/auth/realms/vertx-test")
        .setClientID("public-client"),
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
      AccessToken token = (AccessToken) authn.result();

      keycloak.authenticate(new JsonObject().put("access_token", token.opaqueAccessToken()).put("token_type", "Bearer"), authn2 -> {
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
      AccessToken token = (AccessToken) authn.result();

      // get a auth handler for the confidential client
      KeycloakAuth.discover(
        rule.vertx(),
        new OAuth2ClientOptions()
          .setFlow(OAuth2FlowType.PASSWORD)
          .setSite("http://127.0.0.1:8888/auth/realms/vertx-test")
          .setClientID("confidential-client")
          .setClientSecret("62b8de48-672e-4287-bb1e-6af39aec045e"),
        discover -> {
          should.assertTrue(discover.succeeded());
          OAuth2Auth confidential = discover.result();

          confidential.introspectToken(token.opaqueAccessToken(), introspect -> {
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
      AccessToken token = (AccessToken) authn.result();

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

      final AtomicInteger cnt = new AtomicInteger(roles.size());

      for (String role : roles) {
        token.isAuthorized(role, authz -> {
          should.assertTrue(authz.succeeded());
          should.assertTrue(authz.result());
          if (cnt.decrementAndGet() == 0) {
            test.complete();
          }
        });
      }
    });
  }

  @Test
  public void shouldGetPermissionsFromTokenButPermissionIsNotAllowed(TestContext should) {
    final Async test = should.async();

    keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
      should.assertTrue(authn.succeeded());
      should.assertNotNull(authn.result());

      // generate a access token from the user
      AccessToken token = (AccessToken) authn.result();

      token.isAuthorized("sudo", authz -> {
        should.assertTrue(authz.succeeded());
        should.assertFalse(authz.result());
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
      AccessToken token = (AccessToken) authn.result();

      token.userInfo(userinfo -> {
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
      AccessToken token = (AccessToken) authn.result();

      final String origToken = token.opaqueAccessToken();

      token.refresh(refresh -> {
        should.assertTrue(refresh.succeeded());

        should.assertNotEquals(origToken, token.opaqueAccessToken());
        test.complete();
      });
    });
  }

  @Test
  public void shouldReloadJWK(TestContext should) {
    final Async test = should.async();

    keycloak.loadJWK(load -> {
      should.assertTrue(load.succeeded());

      keycloak.authenticate(new JsonObject().put("username", "test-user").put("password", "tiger"), authn -> {
        should.assertTrue(authn.succeeded());
        should.assertNotNull(authn.result());

        // generate a access token from the user
        AccessToken token = (AccessToken) authn.result();

        should.assertNotNull(token.accessToken());
        test.complete();
      });
    });
  }
}
