package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

public class Oauth2TokenScopeTest extends VertxTestBase {

  private final static String JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InNjb3BlQSBzY29wZUIgc2NvcGVDIiwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjAsImlhdCI6MTQ2NDkwNjY3MSwic3ViIjoiZjE4ODhmNGQtNTE3Mi00MzU5LWJlMGMtYWYzMzg1MDVkODZjIn0.7aJYjGVe4YfdnYTlQH_FYhRCjvctcE7DtWwzxXrbLmM";

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private OAuth2Options oauthConfig;
  private JsonObject fixtureIntrospect;

  @Override
  public void setUp() throws Exception {
    super.setUp();

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
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://localhost:8080");

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/introspect".equals(req.path())) {
          req.setExpectMultipart(true).bodyHandler(buffer -> {
            try {
              JsonObject body = SimpleHttpClient.queryToJson(buffer);
              assertEquals(config.getString("token"), body.getString("token"));
              // conditional test for token_type_hint
              if (config.containsKey("token_type_hint")) {
                assertEquals(config.getString("token_type_hint"), body.getString("token_type_hint"));
              }
            } catch (UnsupportedEncodingException e) {
              fail(e);
            }
            req.response().putHeader("Content-Type", "application/json").end(fixtureIntrospect.encode());
          });
      } else {
        req.response().setStatusCode(400).end();
      }
    }).listen(8080, ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }
      // ready
      latch.countDown();
    });

    latch.await();
  }

  @Override
  public void tearDown() throws Exception {
    server.close();
    super.tearDown();
  }

  /**
   * Token scopes are checked and must be valid.
   * Scopes are retrieved from the JWT itself.
   * JWT generated in HS256 with vertx as shared secret.
   */
  @Test
  public void tokenIsValid() {
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx").setSymmetric(true))
      .setJWTOptions(new JWTOptions().addScope("scopeA").addScope("scopeB"));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      if (res.failed()) {
        fail(res.cause());
      } else {
        User token = res.result();
        assertFalse(token.expired());
        testComplete();
      }
    });
    await();
  }

  /**
   * Token scopes are checked and must be valid.
   * Scopes are retrieved through the token introspection.
   */
  @Test
  public void tokenIsValid_withIntrospection() {
    final String opaqueToken = "opaqueToken";

    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", opaqueToken)
      .put("token", opaqueToken);

    oauthConfig
      .setIntrospectionPath("/oauth/introspect")
      .setJWTOptions(new JWTOptions().addScope("scopeA").addScope("scopeB"));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      if (res.failed()) {
        fail(res.cause());
      } else {
        User token = res.result();
        assertFalse(token.expired());

        ScopeAuthorization.create(" ").getAuthorizations(token, call -> {
          assertTrue(call.succeeded());
          assertTrue(PermissionBasedAuthorization.create("scopeA").match(token));
          assertTrue(PermissionBasedAuthorization.create("scopeB").match(token));
          testComplete();
        });
      }
    });
    await();
  }

  /**
   * Token scopes are checked and scopeX is missing.
   * Scopes are retrieved from the JWT itself.
   * JWT generated in HS256 with vertx as shared secret.
   */
  @Test
  public void tokenIsNotValid() {
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx").setSymmetric(true))
      .setJWTOptions(new JWTOptions().addScope("scopeX").addScope("scopeB"));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      assertTrue(res.succeeded());
      ScopeAuthorization.create(" ").getAuthorizations(res.result(), call -> {
        assertTrue(call.succeeded());
        // the scopes are missing
        assertFalse(PermissionBasedAuthorization.create("scopeX").match(res.result()));
        assertFalse(PermissionBasedAuthorization.create("scopeB").match(res.result()));
        testComplete();
      });
    });
    await();
  }

  /**
   * Token scopes are checked and scopeX is missing.
   * Scopes are retrieved through the token introspection.
   */
  @Test
  public void tokenIsNotValid_withIntrospection() {
    final String opaqueToken = "opaqueToken";

    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", opaqueToken)
      .put("token", opaqueToken);

    oauthConfig
      .setIntrospectionPath("/oauth/introspect")
      .setJWTOptions(new JWTOptions().addScope("scopeX").addScope("scopeB"));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      assertTrue(res.succeeded());
      ScopeAuthorization.create(" ").getAuthorizations(res.result(), call -> {
        assertTrue(call.succeeded());
        assertTrue(PermissionBasedAuthorization.create("scopeA").match(res.result()));
        assertTrue(PermissionBasedAuthorization.create("scopeB").match(res.result()));
        // the scope is missing
        assertFalse(PermissionBasedAuthorization.create("scopeX").match(res.result()));
        testComplete();
      });
    });
    await();
  }

  /**
   * Scopes are not available through the token introspection.
   * Scopes check must not be performed / throw an error.
   */
  @Test
  public void shouldNotFailWhenNoIntrospectionScope() {
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
      .setJWTOptions(new JWTOptions().addScope("scopeX").addScope("scopeB"));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      if (res.failed()) {
        fail("Test should have not failed");
      } else {
        User token = res.result();
        assertEquals("username",token.principal().getValue("username"));
        assertNull(token.principal().getValue("scope"));
        testComplete();
      }
    });
    await();
  }

  /**
   * Scopes are available into the token but no scopes requirement is set.
   */
  @Test
  public void shouldNotFailWhenNoScopeRequired() {
    config = new JsonObject()
      .put("token_type", "Bearer")
      .put("access_token", JWT)
      .put("token", JWT);

    oauthConfig
      .setJWTOptions(new JWTOptions())
      .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer("vertx").setSymmetric(true));

    oauth2 = OAuth2Auth.create(vertx, oauthConfig);

    oauth2.authenticate(config, res -> {
      if (res.failed()) {
        fail("Test should have not failed");
      } else {
        User token = res.result();
        testComplete();
      }
    });
    await();
  }
}
