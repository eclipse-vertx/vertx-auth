package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.stringify;

public class OAuth2PasswordTest extends VertxTestBase {

  private static final JsonObject fixture = new JsonObject(
      "{" +
          "  \"access_token\": \"4adc339e0\"," +
          "  \"refresh_token\": \"ec1a59d298\"," +
          "  \"token_type\": \"bearer\"," +
          "  \"expires_in\": 7200" +
          "}");

  private static final JsonObject tokenConfig = new JsonObject()
      .put("username", "alice")
      .put("password", "secret");

  private static final JsonObject oauthConfig = new JsonObject()
      .put("password", "secret")
      .put("client_secret", "client-secret")
      .put("grant_type", "password")
      .put("client_id", "client-id")
      .put("username", "alice");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.PASSWORD, new JsonObject()
        .put("clientID", "client-id")
        .put("clientSecret", "client-secret")
        .put("site", "http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          // this is a tricky assertion because it assumes the order while it should not matter...
          assertEquals(stringify(config), buffer.toString());
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
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

  @Test
  public void getToken() {
    config = oauthConfig;
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        AccessToken token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());
        testComplete();
      }
    });
    await();
  }
}
