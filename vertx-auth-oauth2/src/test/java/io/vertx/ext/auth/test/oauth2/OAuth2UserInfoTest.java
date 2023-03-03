package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
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
public class OAuth2UserInfoTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  // according to https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
  private static final JsonObject fixture = new JsonObject()
    .put("sub", "248289761001")
    .put("name", "Jane Doe")
    .put("given_name", "Jane")
    .put("family_name", "Doe")
    .put("preferred_username", "j.doe")
    .put("email", "janedoe@example.com")
    .put("picture", "http://example.com/janedoe/me.jpg");

  private static final JsonObject googleParams = new JsonObject()
    .put("alt", "json");

  private OAuth2Auth oauth2;
  private HttpServer server;

  @Before
  public void setUp(TestContext should) {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.GET && "/oauth/userinfo".equals(req.path())) {
        should.assertTrue(req.getHeader("Authorization").contains("Bearer "));

        try {
          should.assertEquals(googleParams, SimpleHttpClient.queryToJson(Buffer.buffer(req.query())));
        } catch (UnsupportedEncodingException e) {
          should.fail(e);
        }

        req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
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
        .setSite("http://localhost:" + ready.result().actualPort())
        .setUserInfoPath("/oauth/userinfo")
        .setUserInfoParameters(googleParams));

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
  public void getUserInfo(TestContext should) {
    final Async test = should.async();
    final User accessToken = User.fromToken("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZV9zZXRfaWQiOiJkMmZlOTg0My02NDYyLTRiZmMtYmFiYS1iNTc4N2JiNmUwZTciLCJyZXNvdXJjZV9zZXRfbmFtZSI6IkhlbGxvIFdvcmxkIFJlc291cmNlIn1dfSwianRpIjoiZDYxMDlhMDktNzhmZC00OTk4LWJmODktOTU3MzBkZmQwODkyLTE0NjQ5MDY2Nzk0MDUiLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjoxNDY0OTA2NjcxLCJzdWIiOiJmMTg4OGY0ZC01MTcyLTQzNTktYmUwYy1hZjMzODUwNWQ4NmMiLCJ0eXAiOiJrY19ldHQiLCJhenAiOiJoZWxsby13b3JsZC1hdXRoei1zZXJ2aWNlIn0");

    oauth2.userInfo(accessToken, userInfo -> {
      if (userInfo.failed()) {
        should.fail(userInfo.cause().getMessage());
      } else {
        test.complete();
      }
    });
  }

  @Test
  public void getUserInfoWithParams(TestContext should) {
    final Async test = should.async();
    final User accessToken = User.fromToken("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZV9zZXRfaWQiOiJkMmZlOTg0My02NDYyLTRiZmMtYmFiYS1iNTc4N2JiNmUwZTciLCJyZXNvdXJjZV9zZXRfbmFtZSI6IkhlbGxvIFdvcmxkIFJlc291cmNlIn1dfSwianRpIjoiZDYxMDlhMDktNzhmZC00OTk4LWJmODktOTU3MzBkZmQwODkyLTE0NjQ5MDY2Nzk0MDUiLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjoxNDY0OTA2NjcxLCJzdWIiOiJmMTg4OGY0ZC01MTcyLTQzNTktYmUwYy1hZjMzODUwNWQ4NmMiLCJ0eXAiOiJrY19ldHQiLCJhenAiOiJoZWxsby13b3JsZC1hdXRoei1zZXJ2aWNlIn0");

    oauth2.userInfo(accessToken, userInfo -> {
      if (userInfo.failed()) {
        should.fail(userInfo.cause().getMessage());
      } else {
        should.assertEquals(fixture, userInfo.result());
        test.complete();
      }
    });
  }
}
