package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.Credentials;
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

@RunWith(VertxUnitRunner.class)
public class OAuth2ErrorsTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final Credentials tokenConfig = new Oauth2Credentials()
    .setFlow(OAuth2FlowType.AUTH_CODE)
    .setCode("code")
    .setRedirectUri("http://callback.com");

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject fixture;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer ->
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode()));
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
    final Async tearDown = should.async();
    server.close()
      .onFailure(should::fail)
      .onSuccess(v -> tearDown.complete());
  }

  @Test
  public void errorAsJson(TestContext should) {
    final Async test = should.async();
    // facebook style
    fixture = new JsonObject()
      .put("error", new JsonObject()
        .put("message", "Error validating access token: User USER_ID has not authorized application APP_ID.")
        .put("type", "OAuthException")
        .put("code", 190));

    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("Error validating access token: User USER_ID has not authorized application APP_ID.", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should fail");
        }
      });
  }

  @Test
  public void errorAsText(TestContext should) {
    final Async test = should.async();
    // github style
    fixture = new JsonObject()
      .put("error", "incorrect_client_credentials")
      .put("error_description", "The client_id and/or client_secret passed are incorrect.")
      .put("error_uri", "https://developer.github.com/v3/oauth/#incorrect-client-credentials");

    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("The client_id and/or client_secret passed are incorrect.", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should fail");
        }
      });
  }

  @Test
  public void errorSimpleText(TestContext should) {
    final Async test = should.async();
    fixture = new JsonObject()
      .put("error", "incorrect_client_credentials");

    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("incorrect_client_credentials", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should fail");
        }
      });
  }

  @Test
  public void errorAsSomethingElse(TestContext should) {
    final Async test = should.async();
    fixture = new JsonObject()
      .put("error", 190);

    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("190", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should fail");
        }
      });
  }
}
