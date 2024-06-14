package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.user.User;
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
public class OAuth2OBOTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixture = new JsonObject(
    "{" +
      "  \"access_token\": \"1/8xbJqaOZXSUZbHLl5EOtu1pxz3fmmetKx9W8CV4t79M\"," +
      "  \"token_type\": \"bearer\"," +
      "  \"expires_in\": 3600" +
      "}");

  protected OAuth2Auth oauth2;
  private HttpServer server;

  @Before
  public void setUp(TestContext should) {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/resource/oauth2/token".equals(req.path())) {
        should.assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            JsonObject payload = SimpleHttpClient.queryToJson(buffer);
            // according to the docs Azure expects the following values:
            should.assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", payload.getString("grant_type"));
            should.assertEquals("head.body.signature", payload.getValue("assertion"));
            // client-id and client-secret are passed in the authorization header
            should.assertEquals("resource", payload.getValue("resource"));
            should.assertEquals("on_behalf_of", payload.getValue("requested_token_use"));
            should.assertEquals("a,b", payload.getValue("scope"));
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

      // mock AzureAD
      oauth2 = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setTenant("resource")
        .setTokenPath("http://localhost:" + ready.result().actualPort() + "/{tenant}/oauth2/token")
        .setAuthorizationPath("http://localhost:" + ready.result().actualPort() + "/{tenant}/oauth2/authorize")
        .setScopeSeparator(",")
        .setExtraParameters(
          new JsonObject().put("resource", "{tenant}")));

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
    oauth2.authenticate(new Oauth2Credentials().setFlow(OAuth2FlowType.AAD_OBO).setAssertion("head.body.signature").addScope("a").addScope("b"))
      .onComplete(res -> {
        if (res.failed()) {
          should.fail(res.cause());
        } else {
          User token = res.result();
          should.assertNotNull(token);
          should.assertNotNull(token.principal());
          test.complete();
        }
      });
  }
}
