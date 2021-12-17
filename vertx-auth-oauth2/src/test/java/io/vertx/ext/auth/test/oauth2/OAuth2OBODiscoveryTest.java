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
import io.vertx.ext.auth.oauth2.Oauth2Credentials;
import io.vertx.ext.auth.oauth2.authorization.ScopeAuthorization;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;
import io.vertx.ext.auth.oauth2.providers.AzureADAuth;
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
public class OAuth2OBODiscoveryTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

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

    // mock AzureAD
    AzureADAuth.discover(
      rule.vertx(),
      new OAuth2Options()
        .setFlow(OAuth2FlowType.AAD_OBO)
        .setClientId("client-id")
        .setClientSecret("client-secret")
        .setTenant("common")
        .setJWTOptions(
          new JWTOptions()
            .addAudience("api://resource")))

      .onFailure(should::fail)
      .onSuccess(oauth2 -> {
        this.oauth2 = oauth2;

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
                should.assertEquals("on_behalf_of", payload.getValue("requested_token_use"));
                should.assertEquals("a b", payload.getValue("scope"));
              } catch (UnsupportedEncodingException e) {
                should.fail(e);
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

          // hack the config to go to the mock
          ((OAuth2AuthProviderImpl) this.oauth2).getConfig()
            .setTokenPath("http://localhost:" + ready.result().actualPort() + "/resource/oauth2/token")
            .setAuthorizationPath("http://localhost:" + ready.result().actualPort() + "/resource/oauth2/authorize");

          // ready
          setup.complete();
        });
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

    // Given that we want to trade an existing token for a new one (On-Behalf-Of) we **must** user OAuth2Credentials
    oauth2.authenticate(new Oauth2Credentials().setAssertion("head.body.signature").addScope("a").addScope("b"), res -> {
      if (res.failed()) {
        should.fail(res.cause());
      } else {
        User token = res.result();
        should.assertNotNull(token);
        should.assertNotNull(token.principal());

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
          should.assertTrue(authz1.succeeded());
          should.assertTrue(PermissionBasedAuthorization.create("user_impersonation").match(token));
          test.complete();
        });
      }
    });
  }
}
