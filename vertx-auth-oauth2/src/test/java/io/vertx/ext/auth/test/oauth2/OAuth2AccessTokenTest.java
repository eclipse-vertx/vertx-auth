package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

public class OAuth2AccessTokenTest extends VertxTestBase {

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
    .put("redirect_uri", "http://callback.com");

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

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://localhost:8080")
      .setHeaders(new JsonObject().put("x-foo", "bar")));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      assertEquals("bar", req.getHeader("x-foo"));
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject expectedRequest = config;

            assertEquals(expectedRequest, SimpleHttpClient.queryToJson(buffer));
          } catch (UnsupportedEncodingException e) {
            fail(e);
          }
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
        });
      } else if (req.method() == HttpMethod.POST && "/oauth/revoke".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          //Revoke does not pass auth details
          JsonObject expectedRequest = removeAuthDetails(config);
          try {
            assertEquals(expectedRequest, SimpleHttpClient.queryToJson(buffer));
          } catch (UnsupportedEncodingException e) {
            fail(e);
          }
          req.response().end();
        });
      } else if (req.method() == HttpMethod.POST && "/oauth/introspect".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            assertEquals(config, SimpleHttpClient.queryToJson(buffer));
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

  private JsonObject removeAuthDetails(JsonObject config) {
    JsonObject request = config.copy();
    request.remove("client_secret");
    request.remove("client_id");
    return request;
  }

  @Override
  public void tearDown() throws Exception {
    server.close();
    super.tearDown();
  }

  @Test
  public void createAccessToken() {
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        User token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());
        testComplete();
      }
    });
    await();
  }

  @Test
  public void tokenShouldNotBeExpired() {
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        User token = res.result();
        assertFalse(token.expired());
        testComplete();
      }
    });
    await();
  }

  @Test
  public void tokenShouldBeExpiredWhenExpirationDateIsInThePast() {
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        User token = res.result();
        // hack the token to set the exp (to yesterday)
        token.attributes().put("exp", System.currentTimeMillis() / 1000 - 24 * 60 * 60);
        assertTrue(token.expired());
        testComplete();
      }
    });
    await();
  }

  @Test
  public void whenRefreshingTokenShouldGetNewAccessToken() {
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause());
      } else {
        User token = res.result();
        // refresh the token
        config = refreshConfig;
        oauth2.refresh(token, v -> {
          if (v.failed()) {
            fail(v.cause().getMessage());
          } else {
            testComplete();
          }
        });
      }
    });
    await();
  }

  @Test
  public void shouldRevokeAToken() {
    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        User token = res.result();
        // refresh the token
        config = revokeConfig;
        oauth2.revoke(token, "refresh_token", v -> {
          if (v.failed()) {
            fail(v.cause().getMessage());
          } else {
            testComplete();
          }
        });
      }
    });
    await();
  }
}
