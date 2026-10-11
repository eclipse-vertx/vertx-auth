package io.vertx.tests;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.OpenIDConnectAuth;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.Collections;

@RunWith(VertxUnitRunner.class)
public class OpenIDCDiscoveryGrantTypesTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private HttpServer server;
  private String site;
  private JsonObject discoveryDocument;

  @Before
  public void setUp(TestContext should) throws Exception {
    final Async setup = should.async();

    server = rule.vertx().createHttpServer().requestHandler(req -> {
      if (req.method() == HttpMethod.GET && "/.well-known/openid-configuration".equals(req.path())) {
        req.response()
          .putHeader("Content-Type", "application/json")
          .end(discoveryDocument.encode());
      } else {
        req.response().setStatusCode(404).end();
      }
    });
    server.listen(0).onComplete(ready -> {
      if (ready.failed()) {
        throw new RuntimeException(ready.cause());
      }
      site = "http://localhost:" + ready.result().actualPort();
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

  private JsonObject baseDiscoveryDocument() {
    return new JsonObject()
      .put("issuer", site)
      .put("authorization_endpoint", site + "/oauth/authorize")
      .put("token_endpoint", site + "/oauth/token");
  }

  @Test
  public void configuredGrantTypesSurviveWhenServerOmitsThem(TestContext should) {
    final Async test = should.async();

    discoveryDocument = baseDiscoveryDocument();

    // a client used only to validate tokens, no clientId is required for the implicit flow
    OpenIDConnectAuth.discover(rule.vertx(), new OAuth2Options()
        .setSite(site)
        .setSupportedGrantTypes(Collections.singletonList("implicit")))
      .onComplete(discovery -> {
        if (discovery.failed()) {
          should.fail(discovery.cause().getMessage());
        } else {
          OAuth2Options config = ((OAuth2AuthProviderImpl) discovery.result()).getConfig();
          should.assertEquals(Collections.singletonList("implicit"), config.getSupportedGrantTypes());
          test.complete();
        }
      });
  }

  @Test
  public void serverGrantTypesReplaceConfiguredOnes(TestContext should) {
    final Async test = should.async();

    discoveryDocument = baseDiscoveryDocument()
      .put("grant_types_supported", new JsonArray().add("authorization_code").add("refresh_token"));

    OpenIDConnectAuth.discover(rule.vertx(), new OAuth2Options()
        .setSite(site)
        .setClientId("client-id")
        .setSupportedGrantTypes(Collections.singletonList("implicit")))
      .onComplete(discovery -> {
        if (discovery.failed()) {
          should.fail(discovery.cause().getMessage());
        } else {
          OAuth2Options config = ((OAuth2AuthProviderImpl) discovery.result()).getConfig();
          should.assertEquals(Arrays.asList("authorization_code", "refresh_token"), config.getSupportedGrantTypes());
          test.complete();
        }
      });
  }

  @Test
  public void missingGrantTypesStillRequireClientIdByDefault(TestContext should) {
    final Async test = should.async();

    discoveryDocument = baseDiscoveryDocument();

    // no grant types configured and none discovered, the defaults require a clientId
    OpenIDConnectAuth.discover(rule.vertx(), new OAuth2Options()
        .setSite(site))
      .onComplete(discovery -> {
        should.assertTrue(discovery.failed());
        should.assertEquals("Configuration missing. You need to specify [clientId]", discovery.cause().getMessage());
        test.complete();
      });
  }
}
