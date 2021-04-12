package io.vertx.ext.auth.test.oauth2;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.CountDownLatch;

import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import org.junit.Test;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.test.core.VertxTestBase;

public class OAuth2AuthCodeTest extends VertxTestBase {

  private static final JsonObject fixtureTokens = new JsonObject(
    "{" +
      "  \"access_token\": \"4adc339e0\"," +
      "  \"refresh_token\": \"ec1a59d298\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 7200" +
      "}");
  private static final JsonObject fixtureJwks = new JsonObject(
    "{\"keys\":" +
      "  [    " +
      "   {" +
      "    \"kty\":\"RSA\"," +
      "    \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
      "    \"e\":\"AQAB\"," +
      "    \"alg\":\"RS256\"," +
      "    \"kid\":\"1\"" +
      "   }" +
      "  ]" +
      "}");

  private static final JsonObject tokenConfig = new JsonObject()
    .put("code", "code")
    .put("redirectUri", "http://callback.com");

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
    oauth2 = OAuth2Auth.create(vertx, new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientId("client-id")
      .setClientSecret("client-secret")
      .setJwkPath("/oauth/jwks")
      .setSite("http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer()
      .connectionHandler(c -> connectionCounter++)
      .requestHandler(req -> {
        if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
          assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
          req.setExpectMultipart(true).bodyHandler(buffer -> {
            try {
              assertEquals(config, SimpleHttpClient.queryToJson(buffer));
            } catch (UnsupportedEncodingException e) {
              fail(e);
            }
            req.response().putHeader("Content-Type", "application/json").end(fixtureTokens.encode());
          });
        } else if (req.method() == HttpMethod.GET && "/oauth/jwks".equals(req.path())) {
          req.bodyHandler(buffer -> {
            req.response().putHeader("Content-Type", "application/json").end(fixtureJwks.encode());
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
    assertEquals(expected, oauth2.authorizeURL(authorizeConfig));
  }

  @Test
  public void getToken() {
    config = oauthConfig;
    oauth2.jWKSet(res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        oauth2.authenticate(tokenConfig, res2 -> {
          if (res2.failed()) {
            fail(res2.cause().getMessage());
          } else {
            User token = res2.result();
            assertNotNull(token);
            assertNotNull(token.principal());
            assertNotNull(token.principal().getString("access_token"));
            testComplete();
          }
        });

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
      .onComplete(r -> {
        if (r.failed()) {
          fail(r.cause());
        } else {
          // on slow environments multiple connections may be used
          assertTrue(connectionCounter < 3);
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
