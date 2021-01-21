package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.impl.http.SimpleHttpClient;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.AzureADAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.CountDownLatch;

public class OAuth2OBODiscoveryTest extends VertxTestBase {

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
    final CountDownLatch latch = new CountDownLatch(1);
    // mock AzureAD
    AzureADAuth.discover(
      vertx,
      new OAuth2Options()
        .setFlow(OAuth2FlowType.AUTH_JWT)
        .setClientID("client-id")
        .setClientSecret("client-secret")
        .setTenant("resource")
        .setJWTOptions(
          new JWTOptions()
            .addAudience("api://resource")))

      .onFailure(this::fail)
      .onSuccess(oauth2 -> {
        this.oauth2 = oauth2;

        // hack the config to go to the mock
        ((OAuth2AuthProviderImpl) this.oauth2).getConfig()
          .setTokenPath("http://localhost:8080/resource/oauth2/token")
          .setAuthorizationPath("http://localhost:8080/resource/oauth2/authorize");

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

        // mock the token
        // with a dump from the official docs:
        token.attributes()
          .put("accessToken", new JsonObject(
            "{\n" +
            "  \"aud\": \"ef1da9d4-ff77-4c3e-a005-840c3f830745\",\n" +
            "  \"iss\": \"https://sts.windows.net/fa15d692-e9c7-4460-a743-29f29522229/\",\n" +
            "  \"iat\": 1537233106,\n" +
            "  \"nbf\": 1537233106,\n" +
            "  \"exp\": 1537237006,\n" +
            "  \"acr\": \"1\",\n" +
            "  \"aio\": \"AXQAi/8IAAAAFm+E/QTG+gFnVxLjWdw8K+61AGrSOuMMF6ebaMj7XO3IbmD3fGmrOyD+NvZyGn2VaT/kDKXw4MIhrgGVq6Bn8wLXoT1LkIZ+FzQVkJPPLQOV4KcXqSlCVPDS/DiCDgE222TImMvWNaEMaUOTsIGvTQ==\",\n" +
            "  \"amr\": [\n" +
            "    \"wia\"\n" +
            "  ],\n" +
            "  \"appid\": \"75dbe77f-10a3-4e59-85fd-8c127544f17c\",\n" +
            "  \"appidacr\": \"0\",\n" +
            "  \"email\": \"AbeLi@microsoft.com\",\n" +
            "  \"family_name\": \"Lincoln\",\n" +
            "  \"given_name\": \"Abe (MSFT)\",\n" +
            "  \"idp\": \"https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd0122247/\",\n" +
            "  \"ipaddr\": \"222.222.222.22\",\n" +
            "  \"name\": \"abeli\",\n" +
            "  \"oid\": \"02223b6b-aa1d-42d4-9ec0-1b2bb9194438\",\n" +
            "  \"rh\": \"I\",\n" +
            "  \"scp\": \"user_impersonation\",\n" +
            "  \"sub\": \"l3_roISQU222bULS9yi2k0XpqpOiMz5H3ZACo1GeXA\",\n" +
            "  \"tid\": \"fa15d692-e9c7-4460-a743-29f2956fd429\",\n" +
            "  \"unique_name\": \"abeli@microsoft.com\",\n" +
            "  \"uti\": \"FVsGxYXI30-TuikuuUoFAA\",\n" +
            "  \"ver\": \"1.0\"\n" +
            "}"));

        ScopeAuthorization.create(" ", "scp").getAuthorizations(token, authz1 -> {
          assertTrue(authz1.succeeded());
          assertTrue(PermissionBasedAuthorization.create("user_impersonation").match(token));
          testComplete();
        });
      }
    });
    await();
  }
}
