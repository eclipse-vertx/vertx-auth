package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.impl.OAuth2TokenImpl;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.queryToJSON;

public class OAuth2UserInfoTest extends VertxTestBase {

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

  private final OAuth2ClientOptions oauthConfig = new OAuth2ClientOptions()
    .setClientID("client-id")
    .setClientSecret("client-secret")
    .setSite("http://localhost:8080")
    .setUserInfoPath("/oauth/userinfo")
    .setUserInfoParameters(googleParams);

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, oauthConfig);

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.GET && "/oauth/userinfo".equals(req.path())) {
        assertTrue(req.getHeader("Authorization").contains("Bearer "));

        try {
          assertEquals(googleParams, queryToJSON(req.query()));
        } catch (UnsupportedEncodingException e) {
          fail(e);
        }

        req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
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
  public void getUserInfo() {
    final AccessToken accessToken = new OAuth2TokenImpl((OAuth2AuthProviderImpl) oauth2, new JsonObject("{\"access_token\":\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZV9zZXRfaWQiOiJkMmZlOTg0My02NDYyLTRiZmMtYmFiYS1iNTc4N2JiNmUwZTciLCJyZXNvdXJjZV9zZXRfbmFtZSI6IkhlbGxvIFdvcmxkIFJlc291cmNlIn1dfSwianRpIjoiZDYxMDlhMDktNzhmZC00OTk4LWJmODktOTU3MzBkZmQwODkyLTE0NjQ5MDY2Nzk0MDUiLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjoxNDY0OTA2NjcxLCJzdWIiOiJmMTg4OGY0ZC01MTcyLTQzNTktYmUwYy1hZjMzODUwNWQ4NmMiLCJ0eXAiOiJrY19ldHQiLCJhenAiOiJoZWxsby13b3JsZC1hdXRoei1zZXJ2aWNlIn0\",\"active\":true,\"scope\":\"scopeA scopeB\",\"client_id\":\"client-id\",\"username\":\"username\",\"token_type\":\"bearer\",\"expires_at\":99999999999000}"));

    accessToken.userInfo(userInfo -> {
      if (userInfo.failed()) {
        fail(userInfo.cause().getMessage());
      } else {
        testComplete();
      }
    });
    await();
  }

  @Test
  public void getUserInfoWithParams() {
    final AccessToken accessToken = new OAuth2TokenImpl((OAuth2AuthProviderImpl) oauth2, new JsonObject("{\"access_token\":\"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZV9zZXRfaWQiOiJkMmZlOTg0My02NDYyLTRiZmMtYmFiYS1iNTc4N2JiNmUwZTciLCJyZXNvdXJjZV9zZXRfbmFtZSI6IkhlbGxvIFdvcmxkIFJlc291cmNlIn1dfSwianRpIjoiZDYxMDlhMDktNzhmZC00OTk4LWJmODktOTU3MzBkZmQwODkyLTE0NjQ5MDY2Nzk0MDUiLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjoxNDY0OTA2NjcxLCJzdWIiOiJmMTg4OGY0ZC01MTcyLTQzNTktYmUwYy1hZjMzODUwNWQ4NmMiLCJ0eXAiOiJrY19ldHQiLCJhenAiOiJoZWxsby13b3JsZC1hdXRoei1zZXJ2aWNlIn0\",\"active\":true,\"scope\":\"scopeA scopeB\",\"client_id\":\"client-id\",\"username\":\"username\",\"token_type\":\"bearer\",\"expires_at\":99999999999000}"));

    accessToken.userInfo(userInfo -> {
      if (userInfo.failed()) {
        fail(userInfo.cause().getMessage());
      } else {
        assertEquals(fixture, userInfo.result());
        testComplete();
      }
    });
    await();
  }
}
