package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.VertxOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.test.core.VertxTestBase;
import io.vertx.test.fakedns.FakeDNSServer;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;
import static org.hamcrest.CoreMatchers.*;

public class OAuth2FailureTest extends VertxTestBase {

  private static final JsonObject tokenConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com");

  private static final JsonObject oauthConfig = new JsonObject()
    .put("code", "code")
    .put("redirect_uri", "http://callback.com")
    .put("grant_type", "authorization_code");

  protected OAuth2Auth oauth2;
  private HttpServer server;
  private JsonObject config;
  private int code;
  private FakeDNSServer dns; // A dns server that resolves nothing, used in for testing unknown host

  @Override
  public void setUp() throws Exception {
    dns = new FakeDNSServer().store(question -> Collections.emptySet());
    dns.start();
    super.setUp();
    oauth2 = OAuth2Auth.create(vertx, new OAuth2ClientOptions()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://localhost:8080"));

    final CountDownLatch latch = new CountDownLatch(1);

    server = vertx.createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.POST && "/oauth/token".equals(req.path())) {
        assertEquals("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=", req.getHeader("Authorization"));
        req.setExpectMultipart(true).bodyHandler(buffer -> {
          try {
            assertEquals(config, queryToJSON(buffer.toString()));
          } catch (UnsupportedEncodingException e) {
            fail(e);
          }
          req.response().setStatusCode(code).end();
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
    dns.stop();
    super.tearDown();
  }

  @Override
  protected VertxOptions getOptions() {
    VertxOptions options = super.getOptions();
    options.getAddressResolverOptions().addServer(dns.localAddress().getAddress().getHostAddress() + ":" + dns.localAddress().getPort());
    options.getAddressResolverOptions().setOptResourceEnabled(false);
    return options;
  }

  @Test
  public void getUnauthorizedToken() {
    config = oauthConfig;
    code = 401;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("Unauthorized", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }

  @Test
  public void getTokenServerCrash() {
    config = oauthConfig;
    code = 500;
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertEquals("Internal Server Error", res.cause().getMessage());
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }

  @Test
  public void unknownHost() {
    OAuth2Auth auth = OAuth2Auth.create(vertx, new OAuth2ClientOptions()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientID("client-id")
      .setClientSecret("client-secret")
      .setSite("http://zlouklfoux.net.com.info.pimpo.molo"));
    auth.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        assertThat(res.cause(), instanceOf(UnknownHostException.class));
        testComplete();
      } else {
        fail("Should have failed");
      }
    });
    await();
  }
}
