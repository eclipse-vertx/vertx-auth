package io.vertx.tests;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
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
public class OAuth2ClientAssertionTest {

  private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  private static final String CLIENT_ASSERTION = "header.payload.signature";

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"4adc339e0\"," +
      "  \"refresh_token\": \"ec1a59d298\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 7200" +
      "}");

  private HttpServer server;
  private JsonObject expectedTokenRequest;
  private int port;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            should.assertEquals(expectedTokenRequest, SimpleHttpClient.queryToJson(buffer));
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
      port = ready.result().actualPort();
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
  public void getTokenWithClientIdAndClientAssertion(TestContext should) {
    final Async test = should.async();

    // providers like Microsoft Entra and Keycloak require the client_id to be
    // present even when the client authenticates with an assertion
    OAuth2Auth oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
      .setClientId("client-id")
      .setClientAssertionType(CLIENT_ASSERTION_TYPE)
      .setClientAssertion(CLIENT_ASSERTION)
      .setSite("http://localhost:" + port));

    expectedTokenRequest = new JsonObject()
      .put("grant_type", "client_credentials")
      .put("client_id", "client-id")
      .put("client_assertion_type", CLIENT_ASSERTION_TYPE)
      .put("client_assertion", CLIENT_ASSERTION);

    oauth2.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.CLIENT))
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
  public void getTokenWithClientAssertionOnly(TestContext should) {
    final Async test = should.async();

    OAuth2Auth oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
      .setClientAssertionType(CLIENT_ASSERTION_TYPE)
      .setClientAssertion(CLIENT_ASSERTION)
      .setSite("http://localhost:" + port));

    expectedTokenRequest = new JsonObject()
      .put("grant_type", "client_credentials")
      .put("client_assertion_type", CLIENT_ASSERTION_TYPE)
      .put("client_assertion", CLIENT_ASSERTION);

    oauth2.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.CLIENT))
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
  public void getTokenWithClientSecretIgnoresClientAssertion(TestContext should) {
    final Async test = should.async();

    // a confidential client authenticates with its secret, the assertion is not sent
    OAuth2Auth oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
      .setClientId("client-id")
      .setClientSecret("client-secret")
      .setUseBasicAuthorization(false)
      .setClientAssertionType(CLIENT_ASSERTION_TYPE)
      .setClientAssertion(CLIENT_ASSERTION)
      .setSite("http://localhost:" + port));

    expectedTokenRequest = new JsonObject()
      .put("grant_type", "client_credentials")
      .put("client_id", "client-id")
      .put("client_secret", "client-secret");

    oauth2.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.CLIENT))
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
