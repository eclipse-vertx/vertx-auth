package io.vertx.tests;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.Oauth2Credentials;
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
public class OAuth2ClientTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"4adc339e0\"," +
      "  \"refresh_token\": \"ec1a59d298\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 7200" +
      "}");

  private static final Credentials tokenConfig = new Oauth2Credentials().setFlow(OAuth2FlowType.CLIENT);

  private static final JsonObject oauthConfig = new JsonObject()
    .put("grant_type", "client_credentials");

  private static final JsonObject oauthConfigWithScopes = new JsonObject()
    .put("grant_type", "client_credentials")
    .put("scope", "scopeA");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        should.assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            should.assertEquals(config, SimpleHttpClient.queryToJson(buffer));
            req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
        });
      } else {
        req.response().setStatusCode(400).end();
      }
    });
    server.listen(8080).onComplete(ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }

      oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setSite("http://localhost:" + ready.result().actualPort()));

      // ready
      setup.complete();
    });
  }

  @After
  public void tearDown(TestContext should) throws Exception {
    final Async tearDown = should.async();
    server.close()
      .onFailure(should::fail)
      .onSuccess(v -> tearDown.complete());
  }

  @Test
  public void getToken(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
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
  public void getTokenWithScopes(TestContext should) {
    final Async test = should.async();
    config = oauthConfigWithScopes;
    oauth2.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.CLIENT).addScope("scopeA"))
      .onComplete(res -> {
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
}
