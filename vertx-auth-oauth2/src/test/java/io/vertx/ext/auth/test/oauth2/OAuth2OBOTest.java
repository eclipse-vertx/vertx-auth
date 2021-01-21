package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

public class OAuth2OBOTest extends VertxTestBase {

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 3600" +
      "}");

  protected OAuth2Auth oauth2;
  private HttpServer server;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    // mock AzureAD
    oauth2 = OAuth2Auth.create(vertx, new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_JWT)
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setTenant("resource")
      .setTokenPath("http://localhost:8080/{tenant}/oauth2/token")
      .setAuthorizationPath("http://localhost:8080/{tenant}/oauth2/authorize")
      .setScopeSeparator(",")
      .setExtraParameters(
        new JsonObject().put("resource", "{tenant}")));


    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/resource/oauth2/token".equals(req.path())) {
        assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject payload = SimpleHttpClient.queryToJson(buffer);
            // according to the docs Azure expects the following values:
            assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", payload.getString("grant_type"));
            assertEquals("head.body.signature", payload.getValue("assertion"));
            // client-id and client-secret are passed in the authorization header
            assertEquals("resource", payload.getValue("resource"));
            assertEquals("on_behalf_of", payload.getValue("requested_token_use"));
            assertEquals("a,b", payload.getValue("scope"));
          } catch (UnsupportedEncodingException e) {
            fail(e);
          }
          req.response().putHeader("Content-Type", "application/json").end(fixture.encode());
        });
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
  public void getToken() {
    oauth2.authenticate(new TokenCredentials("head.body.signature").addScope("a").addScope("b"), res -> {
      if (res.failed()) {
        fail(res.cause());
      } else {
        User token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());
        testComplete();
      }
    });
    await();
  }
}
