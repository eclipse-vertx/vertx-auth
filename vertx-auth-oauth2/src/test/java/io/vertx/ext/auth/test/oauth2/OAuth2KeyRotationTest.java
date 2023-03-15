package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.providers.GoogleAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@RunWith(VertxUnitRunner.class)
public class OAuth2KeyRotationTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private static final JsonObject fixtureJwks = new JsonObject(
    "{\"keys\":" +
      "  [    " +
      "   {" +
      "    \"kty\":\"RSA\"," +
      "    \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
      "    \"e\":\"AQAB\"," +
      "    \"alg\":\"RS256\"," +
      "    \"kid\":\"1\"" +
      "   }" +
      "  ]" +
      "}");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private int connectionCounter;

  final AtomicInteger cnt = new AtomicInteger(0);
  final AtomicLong then = new AtomicLong();

  private Handler<HttpServerRequest> requestHandler;

  @Before
  public void setUp(TestContext should) {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer()
      .connectionHandler(c -> connectionCounter++)
      .requestHandler(req -> {
        if (req.method() == HttpMethod.GET && "/oauth/jwks".equals(req.path())) {
          req.bodyHandler(buffer -> {
            if (cnt.compareAndSet(0, 1)) {
              then.set(System.currentTimeMillis());
              req.response()
                .putHeader("Content-Type", "application/json")
                // we expect a refresh within 5 sec
                .putHeader("Cache-Control", "public, max-age=5, must-revalidate, no-transform")
                .end(fixtureJwks.encode());
              return;
            }
            if (cnt.compareAndSet(1, 2)) {
              requestHandler.handle(req);
            } else {
              should.fail("Too many calls on the mock");
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
          .setJwkPath("/oauth/jwks")
          .setSite("http://localhost:" + ready.result().actualPort()));

        // ready
        setup.complete();
      });

    connectionCounter = 0;
  }

  @After
  public void tearDown(TestContext should) throws Exception {
    final Async tearDown = should.async();
    server.close()
      .onFailure(should::fail)
      .onSuccess(v -> tearDown.complete());
  }

  @Test
  public void testLoadJWK(TestContext should) {
    final Async test = should.async();
    OAuth2Auth oauth2 = GoogleAuth.create(rule.vertx(), "", "");

    oauth2.jWKSet()
      .onFailure(should::fail)
      .onSuccess(load -> test.complete());
  }

  @Test
  public void testAutoRefresh(TestContext should) {
    final Async test = should.async();
    requestHandler = req -> {
      if (then.get() + 5000 <= System.currentTimeMillis()) {
        req.response()
          .putHeader("Content-Type", "application/json")
          .end(fixtureJwks.encode());
        // allow the process to complete
        rule.vertx().runOnContext(n -> test.complete());
      } else {
        should.fail("wrong timing: " + (System.currentTimeMillis() - then.get()));
      }
    };

    oauth2.jWKSet()
      .onFailure(should::fail);
  }

  @Test
  public void testMissingKey(TestContext should) {
    final Async test = should.async();
    requestHandler = req -> {
      if (then.get() + 5000 <= System.currentTimeMillis()) {
        req.response()
          .putHeader("Content-Type", "application/json")
          .end(fixtureJwks.encode());
        // allow the process to complete
        rule.vertx().runOnContext(n -> test.complete());
      } else {
        should.fail("wrong timing: " + (System.currentTimeMillis() - then.get()));
      }
    };

    String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.NYY8FXsouaKSuMafoNshtQ997X4x1Jta0GEtl3BAJGY";

    oauth2.jWKSet()
      .onFailure(should::fail)
      .onSuccess(res -> {
        oauth2
          .missingKeyHandler(kid -> {
            if ("HS256#<null>".equals(kid)) {
              test.complete();
            } else {
              should.fail("wrong key id");
            }
          })
          .authenticate(new TokenCredentials(jwt))
          .onSuccess(user -> should.fail("we don't have such key"));
      });
  }

  @Test
  public void testCloseNoMoreRefresh(TestContext should) {
    final Async test = should.async();
    requestHandler = req -> {
      should.fail("wrong timing: " + (System.currentTimeMillis() - then.get()));
    };

    oauth2.jWKSet()
      .onFailure(should::fail)
      .onSuccess(res -> {
        oauth2.close();
        rule.vertx().setTimer(5500L, v -> test.complete());
      });
  }
}
