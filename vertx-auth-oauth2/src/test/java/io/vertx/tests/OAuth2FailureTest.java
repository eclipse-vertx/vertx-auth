package io.vertx.tests;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
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
import java.net.UnknownHostException;

@RunWith(VertxUnitRunner.class)
public class OAuth2FailureTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final Credentials tokenConfig = new Oauth2Credentials()
    .setFlow(OAuth2FlowType.AUTH_CODE)
    .setCode("code")
    .setRedirectUri("http://callback.com");

  private static final JsonObject oauthConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com")
    .put("grant_type", "authorization_code");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private int code;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        should.assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            should.assertEquals(config, SimpleHttpClient.queryToJson(buffer));
          } catch (UnsupportedEncodingException e) {
            should.fail(e);
          }
          req.response().setStatusCode(code).end();
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
  public void getUnauthorizedToken(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    code = 401;
    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("Unauthorized", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should have failed");
        }
      });
  }

  @Test
  public void getTokenServerCrash(TestContext should) {
    final Async test = should.async();
    config = oauthConfig;
    code = 500;
    oauth2.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertEquals("Internal Server Error", res.cause().getMessage());
          test.complete();
        } else {
          should.fail("Should have failed");
        }
      });
  }

  @Test
  public void unknownHost(TestContext should) {
    final Async test = should.async();
    OAuth2Auth auth = OAuth2Auth.create(rule.vertx(), new OAuth2Options()
      .setClientId("client-id")
      .setClientSecret("client-secret")
      .setSite("http://zlouklfoux.net.com.info.pimpo.molo"));
    auth.authenticate(tokenConfig)
      .onComplete(res -> {
        if (res.failed()) {
          should.assertTrue(res.cause() instanceof UnknownHostException);
          test.complete();
        } else {
          should.fail("Should have failed");
        }
      });
  }
}
