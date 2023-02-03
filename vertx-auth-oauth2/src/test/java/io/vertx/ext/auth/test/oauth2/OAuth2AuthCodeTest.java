package io.vertx.ext.auth.test.oauth2;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2AuthorizationURL;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
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
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class OAuth2AuthCodeTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

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
  private int currentPort;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();
    server = rule.vertx().createHttpServer()
      .connectionHandler(c -> connectionCounter++)
      .requestHandler(req -> {
        if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
          should.assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
          req.setExpectMultipart(true).bodyHandler(buffer -> {
            try {
              should.assertEquals(config, SimpleHttpClient.queryToJson(buffer));
              req.response().putHeader("Content-Type", "application/json").end(fixtureTokens.encode());
            } catch (UnsupportedEncodingException e) {
              should.fail(e);
            }
          });
        } else if (req.method() == HttpMethod.GET && "/oauth/jwks".equals(req.path())) {
          req.bodyHandler(buffer -> {
            req.response().putHeader("Content-Type", "application/json").end(fixtureJwks.encode());
          });
        } else {
          req.response().setStatusCode(400).end();
        }
      })
      .listen(0, ready -> {
        if (ready.failed()) {
          throw new RuntimeException(ready.cause());
        }

        oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
          .setFlow(OAuth2FlowType.AUTH_CODE)
          .setClientId("client-id")
          .setClientSecret("client-secret")
          .setJwkPath("/oauth/jwks")
          .setSite("http://localhost:" + ready.result().actualPort()));

        currentPort = ready.result().actualPort();
        // ready
        setup.complete();
      });

    connectionCounter = 0;
  }

  @After
  public void tearDown(TestContext should) throws Exception {
    final Async after = should.async();
    server.close()
      .onFailure(should::fail)
      .onSuccess(v -> after.complete());
  }

  @Test
  public void generateAuthorizeURL(TestContext should) throws Exception {
    String expected = "http://localhost:" + currentPort + "/oauth/authorize?redirect_uri=" + URLEncoder.encode("http://localhost:3000/callback", "UTF-8") + "&scope=user&state=02afe928b&response_type=code&client_id=client-id";
    should.assertEquals(expected, oauth2.authorizeURL(authorizeConfig));
  }

  @Test
  public void generateAuthorizeURLTypeSafe(TestContext should) throws Exception {
    String expected = "http://localhost:" + currentPort + "/oauth/authorize?state=02afe928b&scope=user&response_type=code&client_id=client-id&redirect_uri=" + URLEncoder.encode("http://localhost:3000/callback", "UTF-8") + "&login_hint=my-username&prompt=none+login+consent";
    should.assertEquals(expected, oauth2.authorizeURL(new OAuth2AuthorizationURL()
      .setState(authorizeConfig.getString("state"))
      .setRedirectUri(authorizeConfig.getString("redirect_uri"))
      .addScope(authorizeConfig.getString("scope"))
      .addAdditionalParameter("login_hint", "my-username")
      .addAdditionalParameter("prompt", "none login consent")));
  }

  @Test
  public void getToken(TestContext should) {
    final Async test = should.async();

    config = oauthConfig;
    oauth2.jWKSet(res -> {
      if (res.failed()) {
        should.fail(res.cause().getMessage());
      } else {
        oauth2.authenticate(tokenConfig, res2 -> {
          if (res2.failed()) {
            should.fail(res2.cause().getMessage());
          } else {
            User token = res2.result();
            should.assertNotNull(token);
            should.assertNotNull(token.principal());
            should.assertNotNull(token.principal().getString("access_token"));
            test.complete();
          }
        });
      }
    });
  }

  @Test
  public void testConnectionReuse(TestContext should) {
    final Async test = should.async();
    auth()
      .compose(x -> auth())
      .compose(x -> auth())
      .compose(x -> auth())
      .onComplete(r -> {
        if (r.failed()) {
          should.fail(r.cause());
        } else {
          // on slow environments multiple connections may be used
          should.assertTrue(connectionCounter < 3);
          test.complete();
        }
      });
  }

  Future<Void> auth() {
    config = oauthConfig;
    Promise<User> promise = Promise.promise();
    oauth2.authenticate(tokenConfig, promise);
    return promise.future().mapEmpty();
  }
}
