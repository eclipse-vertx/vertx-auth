package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.UnsupportedEncodingException;

@RunWith(VertxUnitRunner.class)
public class Oauth2TokenScopeTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private final static String JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InNjb3BlQSBzY29wZUIgc2NvcGVDIiwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjAsImlhdCI6MTQ2NDkwNjY3MSwic3ViIjoiZjE4ODhmNGQtNTE3Mi00MzU5LWJlMGMtYWYzMzg1MDVkODZjIn0.7aJYjGVe4YfdnYTlQH_FYhRCjvctcE7DtWwzxXrbLmM";

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private OAuth2Options oauthConfig;
  private JsonObject fixtureIntrospect;

  @Before
  public void setUp(TestContext should) {
    final Async setup = should.async();

    fixtureIntrospect = new JsonObject(
      "{" +
        "  \"active\": true," +
        "  \"scope\": \"scopeA scopeB\"," +
        "  \"client_id\": \"client-id\"," +
        "  \"username\": \"username\"," +
        "  \"token_type\": \"bearer\"," +
        "  \"exp\": 99999999999," +
        "  \"iat\": 7200," +
        "  \"nbf\": 7200" +
        "}");

    oauthConfig = new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientId("client-id")
      .setClientSecret("client-secret");

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/introspect".equals(req.path())) {
          req.setExpectMultipart(true).bodyHandler(buffer -> {
            try {
              JsonObject body = SimpleHttpClient.queryToJson(buffer);
              should.assertEquals(config.getString("token"), body.getString("token"));
              // conditional test for token_type_hint
              if (config.containsKey("token_type_hint")) {
                should.assertEquals(config.getString("token_type_hint"), body.getString("token_type_hint"));
              }
            } catch (UnsupportedEncodingException e) {
              should.fail(e);
            }
            req.response().putHeader("Content-Type", "application/json").end(fixtureIntrospect.encode());
          });
      } else {
        req.response().setStatusCode(400).end();
      }
    }).listen(0, ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      } else {
        int actualPort = ready.result().actualPort();
        oauthConfig
          .setSite("http://localhost:" + actualPort);
      }
      // ready
      setup.complete();
    });
  }

  @After
  public void tearDown(TestContext should) throws Exception {
    final Async tearDown = should.async();
    server.close()
      .onFailure(should::fail)
      .onSuccess(v -> tearDown.complete());
  }

  /**
   * Token scopes are checked and must be valid.
   * Scopes are retrieved from the JWT itself.
   * JWT generated in HS256 with vertx as shared secret.
   */
  @Test
  public void tokenIsValid(TestContext should) {
    final Async test = should.async();
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx"))
      .setJWTOptions(new JWTOptions());

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(JWT), res -> {
      if (res.failed()) {
        should.fail(res.cause());
      } else {
        User token = res.result();
        should.assertFalse(token.expired());
        test.complete();
      }
    });
  }

  /**
   * Token scopes are checked and must be valid.
   * Scopes are retrieved through the token introspection.
   */
  @Test
  public void tokenIsValid_withIntrospection(TestContext should) {
    final Async test = should.async();
    final String opaqueToken = "opaqueToken";

    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", opaqueToken)
      .put("token", opaqueToken);

    oauthConfig
      .setIntrospectionPath("/oauth/introspect")
      .setJWTOptions(new JWTOptions());

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(opaqueToken), res -> {
      if (res.failed()) {
        should.fail(res.cause());
      } else {
        User token = res.result();
        should.assertFalse(token.expired());

        ScopeAuthorization.create(" ").getAuthorizations(token, call -> {
          should.assertTrue(call.succeeded());
          should.assertTrue(PermissionBasedAuthorization.create("scopeA").match(token));
          should.assertTrue(PermissionBasedAuthorization.create("scopeB").match(token));
          test.complete();
        });
      }
    });
  }

  /**
   * Token scopes are checked and scopeX is missing.
   * Scopes are retrieved from the JWT itself.
   * JWT generated in HS256 with vertx as shared secret.
   */
  @Test
  public void tokenIsNotValid(TestContext should) {
    final Async test = should.async();
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx"))
      .setJWTOptions(new JWTOptions());

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(JWT), res -> {
      should.assertTrue(res.succeeded());
      ScopeAuthorization.create(" ").getAuthorizations(res.result(), call -> {
        should.assertTrue(call.succeeded());
        // the scopes are missing
        should.assertFalse(PermissionBasedAuthorization.create("scopeX").match(res.result()));
        should.assertFalse(PermissionBasedAuthorization.create("scopeB").match(res.result()));
        test.complete();
      });
    });
  }

  /**
   * Token scopes are checked and scopeX is missing.
   * Scopes are retrieved through the token introspection.
   */
  @Test
  public void tokenIsNotValid_withIntrospection(TestContext should) {
    final Async test = should.async();
    final String opaqueToken = "opaqueToken";

    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", opaqueToken)
      .put("token", opaqueToken);

    oauthConfig
      .setIntrospectionPath("/oauth/introspect")
      .setJWTOptions(new JWTOptions());

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(opaqueToken), res -> {
      should.assertTrue(res.succeeded());
      ScopeAuthorization.create(" ").getAuthorizations(res.result(), call -> {
        should.assertTrue(call.succeeded());
        should.assertTrue(PermissionBasedAuthorization.create("scopeA").match(res.result()));
        should.assertTrue(PermissionBasedAuthorization.create("scopeB").match(res.result()));
        // the scope is missing
        should.assertFalse(PermissionBasedAuthorization.create("scopeX").match(res.result()));
        test.complete();
      });
    });
  }

  /**
   * Scopes are not available through the token introspection.
   * Scopes check must not be performed / throw an error.
   */
  @Test
  public void shouldNotFailWhenNoIntrospectionScope(TestContext should) {
    final Async test = should.async();
    final String opaqueToken = "opaqueToken";

    this.fixtureIntrospect = new JsonObject(
      "{" +
        "  \"active\": true," +
        //"  \"scope\": \"scopeA scopeB\"," +
        "  \"client_id\": \"client-id\"," +
        "  \"username\": \"username\"," +
        "  \"token_type\": \"bearer\"," +
        "  \"exp\": 99999999999," +
        "  \"iat\": 7200," +
        "  \"nbf\": 7200" +
        "}");

    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", opaqueToken)
      .put("token", opaqueToken);

    oauthConfig
      .setIntrospectionPath("/oauth/introspect")
      .setJWTOptions(new JWTOptions());

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(opaqueToken), res -> {
      if (res.failed()) {
        should.fail("Test should have not failed");
      } else {
        User token = res.result();
        should.assertEquals("username",token.principal().getValue("username"));
        should.assertNull(token.principal().getValue("scope"));
        test.complete();
      }
    });
  }

  /**
   * Scopes are available into the token but no scopes requirement is set.
   */
  @Test
  public void shouldNotFailWhenNoScopeRequired(TestContext should) {
    final Async test = should.async();
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .setJWTOptions(new JWTOptions())
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx"));

    oauth2 = OAuth2Auth.create(rule.vertx(), oauthConfig);

    oauth2.authenticate(new TokenCredentials(JWT), res -> {
      if (res.failed()) {
        should.fail("Test should have not failed");
      } else {
        User token = res.result();
        should.assertNotNull(token);
        test.complete();
      }
    });
  }
}
