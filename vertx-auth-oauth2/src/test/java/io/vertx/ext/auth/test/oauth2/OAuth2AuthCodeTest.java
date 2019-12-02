package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.queryToJSON;

public class OAuth2AuthCodeTest extends VertxTestBase {

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"4adc339e0\"," +
      "  \"refresh_token\": \"ec1a59d298\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 7200" +
      "}");

  private static final JsonObject tokenConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com");

  private static final JsonObject oauthConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com")
    .put("grant_type", "authorization_code");

  private static final JsonObject authorizeConfig = new JsonObject()
    .put("redirect_uri", "http://localhost:3000/callback")
    .put("scope", "user")
    .put("state", "02afe928b");


  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private int connectionCounter;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, new OAuth2ClientOptions()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer()
      .connectionHandler(c -> connectionCounter++)
      .requestHandler(req -> {
        if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
          assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
          req.setExpectMultipart(true).bodyHandler(buffer -> {
            try {
              assertEquals(config, queryToJSON(buffer.toString()));
            } catch (UnsupportedEncodingException e) {
              fail(e);
            }
            req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
          });
        } else {
          req.response().setStatusCode(400).end();
        }
      })
      .listen(8080, ready -> {
        if (ready.failed()) {
          throw new RuntimeException(ready.cause());
        }
        // ready
        latch.countDown();
      });

    connectionCounter = 0;
    latch.await();
  }

  @Override
  public void tearDown() throws Exception {
    server.close();
    super.tearDown();
  }

  @Test
  public void generateAuthorizeURL() throws Exception {
    String expected = "http://localhost:8080/oauth/authorize?redirect_uri=" + URLEncoder.encode("http://localhost:3000/callback", "UTF-8") + "&scope=user&state=02afe928b&response_type=code&client_id=client-id";
    oauth2.authorizeURL(authorizeConfig, authorizeURL -> {
      assertTrue(authorizeURL.succeeded());
      assertEquals(expected, authorizeURL.result());
      testComplete();
    });
    await();
  }

  @Test
  public void getToken() {
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
  public void testConnectionReuse() {
    auth()
      .compose(x -> auth())
      .compose(x -> auth())
      .compose(x -> auth())
      .setHandler(r -> {
        if (r.failed()) {
          fail(r.cause());
        } else {
          assertEquals(1, connectionCounter);
          testComplete();
        }
      });
    await();
  }

  Future<Void> auth() {
    config = oauthConfig;
    Promise<User> promise = Promise.promise();
    oauth2.authenticate(tokenConfig, promise);
    return promise.future().mapEmpty();
  }
}
