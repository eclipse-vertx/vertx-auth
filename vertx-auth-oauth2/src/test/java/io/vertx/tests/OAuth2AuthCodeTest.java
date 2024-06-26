package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.*;
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
import java.net.URLEncoder;

@RunWith(VertxUnitRunner.class)
public class OAuth2AuthCodeTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

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

  private static final Credentials tokenConfig = new Oauth2Credentials()
    .setFlow(OAuth2FlowType.AUTH_CODE)
    .setCode("code")
    .setRedirectUri("http://callback.com");

  private static final JsonObject oauthConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com")
    .put("grant_type", "authorization_code");

  private static final OAuth2AuthorizationURL authorizeConfig = new OAuth2AuthorizationURL()
    .setRedirectUri("http://localhost:3000/callback")
    .addScope("user")
    .setState("02afe928b");


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
      });
    server.listen(0).onComplete(ready -> {
        if (ready.failed()) {
          throw new RuntimeException(ready.cause());
        }

        oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
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
    String expected = "http://localhost:" + currentPort + "/oauth/authorize?redirect_uri=" + URLEncoder.encode("http://localhost:3000/callback", "UTF-8") + "&state=02afe928b&scope=user&response_type=code&client_id=client-id";
    should.assertEquals(expected, oauth2.authorizeURL(authorizeConfig));
  }

  @Test
  public void generateAuthorizeURLTypeSafe(TestContext should) throws Exception {
    String expected = "http://localhost:" + currentPort + "/oauth/authorize?prompt=none+login+consent&login_hint=my-username&redirect_uri=" + URLEncoder.encode("http://localhost:3000/callback", "UTF-8") + "&state=02afe928b&scope=user&response_type=code&client_id=client-id";
    should.assertEquals(expected, oauth2.authorizeURL(new OAuth2AuthorizationURL(authorizeConfig)
      .setLoginHint("my-username")
      .setPrompt("none login consent")));
  }

  @Test
  public void getToken(TestContext should) {
    final Async test = should.async();

    config = oauthConfig;
    oauth2.jWKSet()
      .onFailure(should::fail)
      .onSuccess(v -> {
        oauth2.authenticate(tokenConfig)
          .onFailure(should::fail)
          .onSuccess(token -> {
            should.assertNotNull(token);
            should.assertNotNull(token.principal());
            should.assertNotNull(token.principal().getString("access_token"));
            test.complete();
          });
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
    return oauth2
      .authenticate(tokenConfig)
      .mapEmpty();
  }
}
