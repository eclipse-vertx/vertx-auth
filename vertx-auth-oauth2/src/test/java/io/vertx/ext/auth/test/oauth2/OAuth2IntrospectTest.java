package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
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
public class OAuth2IntrospectTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  // according to RFC
  private static final JsonObject fixtureIntrospect = new JsonObject(
    "{" +
      "  \"active\": true," +
      "  \"scope\": \"scopeA scopeB\"," +
      "  \"client_id\": \"client-id\"," +
      "  \"username\": \"username\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"exp\": 99999999999," +
      "  \"iat\": 7200," +
      "  \"nbf\": 7200" +
      "}");

  // according to Google
  private static final JsonObject fixtureGoogle = new JsonObject(
    "{" +
      "  \"audience\": \"8819981768.apps.googleusercontent.com\"," +
      "  \"user_id\": \"123456789\"," +
      "  \"scope\": \"profile email\"," +
      "  \"expires_in\": 436" +
      "}");

  // according to Keycloak
  private static final JsonObject fixtureKeycloak = new JsonObject(
    "{" +
      "  \"active\": true," +
      "  \"exp\": 99999999999," +
      "  \"iat\": 1465313839," +
      "  \"aud\": \"hello-world-authz-service\",\n" +
      "  \"nbf\": 0" +
      "}");

  private static final String token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdXRob3JpemF0aW9uIjp7InBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZV9zZXRfaWQiOiJkMmZlOTg0My02NDYyLTRiZmMtYmFiYS1iNTc4N2JiNmUwZTciLCJyZXNvdXJjZV9zZXRfbmFtZSI6IkhlbGxvIFdvcmxkIFJlc291cmNlIn1dfSwianRpIjoiZDYxMDlhMDktNzhmZC00OTk4LWJmODktOTU3MzBkZmQwODkyLTE0NjQ5MDY2Nzk0MDUiLCJleHAiOjk5OTk5OTk5OTksIm5iZiI6MCwiaWF0IjoxNDY0OTA2NjcxLCJzdWIiOiJmMTg4OGY0ZC01MTcyLTQzNTktYmUwYy1hZjMzODUwNWQ4NmMiLCJ0eXAiOiJrY19ldHQiLCJhenAiOiJoZWxsby13b3JsZC1hdXRoei1zZXJ2aWNlIn0";

  private static final JsonObject oauthIntrospect = new JsonObject()
    .put("token", token);

  private OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private JsonObject fixture;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/introspect".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject body = SimpleHttpClient.queryToJson(buffer);
            should.assertEquals(config.getString("token"), body.getString("token"));
            // conditional test for token_type_hint
            if (config.containsKey("token_type_hint")) {
              should.assertEquals(config.getString("token_type_hint"), body.getString("token_type_hint"));
            }
            req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
        });
      } else if (req.method() == HttpMethod.POST && "/oauth/tokeninfo".equals(req.path())) {
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
    server.listen(0).onComplete(ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }

      oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setSite("http://localhost:" + ready.result().actualPort())
        .setIntrospectionPath("/oauth/introspect"));

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
  public void introspectAccessToken(TestContext should) {
    final Async test = should.async();

    config = oauthIntrospect;
    fixture = fixtureIntrospect;
    oauth2.authenticate(new TokenCredentials(token))
      .onComplete(res -> {
        if (res.failed()) {
          should.fail(res.cause().getMessage());
        } else {
          User token2 = res.result();
          should.assertNotNull(token2);
          JsonObject principal = token2.principal().copy();

          final JsonObject assertion = fixtureIntrospect.copy();
          // principal should be identified as opaque
          assertion.put("opaque", true);
          // access token should be present in the principal
          assertion.put("access_token", token);

          should.assertEquals(assertion.getMap(), principal.getMap());

          ScopeAuthorization.create(" ").getAuthorizations(token2)
            .onComplete(res0 -> {
              if (res0.failed()) {
                should.fail(res0.cause().getMessage());
              } else {
                if (PermissionBasedAuthorization.create("scopeB").match(token2)) {
                  test.complete();
                } else {
                  should.fail("Should be allowed");
                }
              }
            });
        }
      });
  }

  @Test
  public void introspectAccessTokenGoogleWay(TestContext should) {
    final Async test = should.async();
    config = oauthIntrospect;
    fixture = fixtureGoogle;
    oauth2.authenticate(new TokenCredentials(token))
      .onComplete(res -> {
        if (res.failed()) {
          should.fail(res.cause().getMessage());
        } else {
          User token = res.result();
          should.assertNotNull(token);
          // make a copy because later we need to original data
          JsonObject principal = token.principal().copy();

          // clean up control
          final JsonObject assertion = fixtureGoogle.copy();
          // principal should be identified as opaque
          assertion.put("opaque", true);
          // access token should be present in the principal
          assertion.put("access_token", OAuth2IntrospectTest.token);

          should.assertEquals(assertion.getMap(), principal.getMap());

          ScopeAuthorization.create(" ").getAuthorizations(token)
            .onComplete(res0 -> {
              if (res0.failed()) {
                should.fail(res0.cause().getMessage());
              } else {
                if (PermissionBasedAuthorization.create("profile").match(token)) {
                  // Issue #142

                  // the test is a replay of the same test so all checks have
                  // been done above.

                  // the replay shows that the api can be used from the user object
                  // directly too
                  oauth2.authenticate(new TokenCredentials(OAuth2IntrospectTest.token))
                    .onComplete(v -> {
                      if (v.failed()) {
                        should.fail(v.cause());
                      } else {
                        test.complete();
                      }
                    });
                } else {
                  should.fail("Should be allowed");
                }
              }
            });
        }
      });
  }

  @Test
  public void introspectAccessTokenKeyCloakWay(TestContext should) {
    final Async test = should.async();
    config = oauthIntrospect;
    fixture = fixtureKeycloak;
    oauth2.authenticate(new TokenCredentials(token))
      .onComplete(res -> {
        if (res.failed()) {
          should.fail(res.cause());
        } else {
          User token = res.result();
          should.assertNotNull(token);
          // make a copy because later we need to original data
          JsonObject principal = token.principal().copy();

          // clean up control
          final JsonObject assertion = fixtureKeycloak.copy();
          // principal should be identified as opaque
          assertion.put("opaque", true);
          // access token should be present in the principal
          assertion.put("access_token", OAuth2IntrospectTest.token);

          should.assertEquals(assertion.getMap(), principal.getMap());
          test.complete();
        }
      });
  }
}
