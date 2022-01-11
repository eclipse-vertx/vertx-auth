package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
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
public class OAuth2AccessTokenTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"4adc339e0\"," +
      "  \"refresh_token\": \"ec1a59d298\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 7200" +
      "}");

  private static final JsonObject fixtureIntrospect = new JsonObject(
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

  private static final JsonObject tokenConfig = new JsonObject()
    .put("code", "code")
    .put("redirectUri", "http://callback.com");

  private static final JsonObject refreshConfig = new JsonObject()
    .put("refresh_token", "ec1a59d298")
    .put("grant_type", "refresh_token");

  private static final JsonObject revokeConfig = new JsonObject()
    .put("token_type_hint", "refresh_token")
    .put("client_secret", "client-secret")
    .put("client_id", "client-id")
    .put("token", "ec1a59d298");

  private static final JsonObject oauthConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com")
    .put("grant_type", "authorization_code");

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();
    final Vertx vertx = rule.vertx();

    server = vertx.createHttpServer().requestHandler(req -> {
      should.assertEquals("bar", req.getHeader("x-foo"));
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        should.assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject expectedRequest = config;

            should.assertEquals(expectedRequest, SimpleHttpClient.queryToJson(buffer));
            req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
        });
      } else if (req.method() == HttpMethod.POST && "/oauth/revoke".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          //Revoke does not pass auth details
          JsonObject expectedRequest = removeAuthDetails(config);
          try {
            should.assertEquals(expectedRequest, SimpleHttpClient.queryToJson(buffer));
            req.response().end();
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
        });
      } else if (req.method() == HttpMethod.POST && "/oauth/introspect".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            should.assertEquals(config, SimpleHttpClient.queryToJson(buffer));
            req.response().putHeader("Content-Type", "application/json").end(fixtureIntrospect.encode());
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
        });
      } else {
        req.response().setStatusCode(400).end();
      }
    }).listen(0, ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }

      oauth2 = OAuth2Auth.create(vertx, new OAuth2Options()
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setSite("http://localhost:" + ready.result().actualPort())
        .setHeaders(new JsonObject().put("x-foo", "bar")));

      setup.complete();
    });
  }

  private JsonObject removeAuthDetails(JsonObject config) {
    JsonObject request = config.copy();
    request.remove("client_secret");
    request.remove("client_id");
    return request;
  }

  @After
  public void tearDown(TestContext should) {
    final Async after = should.async();
    server.close()
      .onSuccess(v -> after.complete())
      .onFailure(should::fail);
  }

  @Test
  public void createAccessToken(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause().getMessage());
      } else {
        User token = res.result();
        should.assertNotNull(token);
        should.assertNotNull(token.principal());
        test.complete();
      }
    });
  }

  @Test
  public void tokenShouldNotBeExpired(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause().getMessage());
      } else {
        User token = res.result();
        should.assertFalse(token.expired());
        test.complete();
      }
    });
  }

  @Test
  public void tokenShouldBeExpiredWhenExpirationDateIsInThePast(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause().getMessage());
      } else {
        User token = res.result();
        // hack the token to set the exp (to yesterday)
        token.attributes().put("exp", System.currentTimeMillis() / 1000 - 24 * 60 * 60);
        should.assertTrue(token.expired());
        test.complete();
      }
    });
  }

  @Test
  public void whenRefreshingTokenShouldGetNewAccessToken(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause());
      } else {
        User token = res.result();
        // refresh the token
        config = refreshConfig;
        oauth2.refresh(token, v -> {
          if (v.failed()) {
            should.fail(v.cause().getMessage());
          } else {
            test.complete();
          }
        });
      }
    });
  }

  @Test
  public void whenRefreshingTokenIsNotPresent(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause());
      } else {
        User token = res.result();
        //Clear refresh token
        token.principal().clear();
        oauth2.refresh(token, v -> {
          if (v.failed()) {
            should.assertTrue(v.cause() instanceof IllegalStateException);
            should.assertEquals(v.cause().getMessage(), "refresh_token is null or empty");
            test.complete();
          } else {
            should.fail("This should fail");
          }
        });
      }
    });
  }

  @Test
  public void shouldRevokeAToken(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.fail(res.cause().getMessage());
      } else {
        User token = res.result();
        // refresh the token
        config = revokeConfig;
        oauth2.revoke(token, "refresh_token", v -> {
          if (v.failed()) {
            should.fail(v.cause().getMessage());
          } else {
            test.complete();
          }
        });
      }
    });
  }
}
