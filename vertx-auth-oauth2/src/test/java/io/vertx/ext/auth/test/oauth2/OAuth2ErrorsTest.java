package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;

public class OAuth2ErrorsTest extends VertxTestBase {

  private static final JsonObject tokenConfig = new JsonObject()
      .put("code", "code")
      .put("redirect_uri", "http://callback.com");

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject fixture;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, new OAuth2ClientOptions()
      .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientID("client-id")
        .setClientSecret("client-secret")
        .setSite("http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer ->
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode()));
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
  public void errorAsJson() {
    // facebook style
    fixture = new JsonObject()
      .put("error", new JsonObject()
        .put("message", "Error validating access token: User USER_ID has not authorized application APP_ID.")
        .put("type", "OAuthException")
        .put("code", 190));

    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("Error validating access token: User USER_ID has not authorized application APP_ID.", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should fail");
      }
    });
    await();
  }

  @Test
  public void errorAsText() {
    // github style
    fixture = new JsonObject()
      .put("error", "incorrect_client_credentials")
      .put("error_description", "The client_id and/or client_secret passed are incorrect.")
      .put("error_uri", "https://developer.github.com/v3/oauth/#incorrect-client-credentials");

    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("The client_id and/or client_secret passed are incorrect.", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should fail");
      }
    });
    await();
  }

  @Test
  public void errorSimpleText() {
    fixture = new JsonObject()
      .put("error", "incorrect_client_credentials");

    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("incorrect_client_credentials", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should fail");
      }
    });
    await();
  }

  @Test
  public void errorAsSomethingElse() {
    fixture = new JsonObject()
      .put("error", 190);

    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("190", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should fail");
      }
    });
    await();
  }
}
