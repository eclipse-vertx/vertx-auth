package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
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
public class OAuth2AuthCodeErrorTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"error\": \"bad_verification_code\"," +
      "  \"error_description\": \"bad verification code\"" +
      "}");

  private static final Credentials tokenConfig = new Oauth2Credentials()
    .setCode("code")
    .setRedirectUri("http://callback.com");

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
    }).listen(0, ready -> {
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
    final Async cleanup = should.async();
    server.close()
      .onSuccess(v -> cleanup.complete())
      .onFailure(should::fail);
  }

  @Test
  public void getToken(TestContext should) {
    final Async test = should.async();

    config = oauthConfig;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        should.assertNotNull(res.cause());
        test.complete();
      } else {
        should.fail("Should fail with bad verification code");
      }
    });
  }
}
