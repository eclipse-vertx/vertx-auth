package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;
import static org.hamcrest.CoreMatchers.*;

public class OAuth2FailureTest extends VertxTestBase {

  private static final JsonObject tokenConfig = new JsonObject()
      .put("code", "code")
      .put("redirect_uri", "http://callback.com");

  private static final JsonObject oauthConfig = new JsonObject()
      .put("code", "code")
      .put("redirect_uri", "http://callback.com")
      .put("client_secret", "client-secret")
      .put("grant_type", "authorization_code")
      .put("client_id", "client-id");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private int code;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
        .setClientID("client-id")
        .setClientSecret("client-secret")
        .setSite("http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          // this is a tricky assertion because it assumes the order while it should not matter...
          assertEquals(stringify(config), buffer.toString());
          req.response().setStatusCode(code).end();
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
  public void getUnauthorizedToken() {
    config = oauthConfig;
    code = 401;
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("Unauthorized", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }

  @Test
  public void getTokenServerCrash() {
    config = oauthConfig;
    code = 500;
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("Internal Server Error", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }

  @Test
  public void unknownHost() {
    OAuth2Auth auth = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://zlouklfoux.net.com.info.pimpo.molo"));
    auth.getToken(tokenConfig, res -> {
      if (res.failed()) {
        assertThat(res.cause(), instanceOf(UnknownHostException.class));
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }
}
