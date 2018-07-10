package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.providers.OpenIDConnectAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

public class OIDCTest extends VertxTestBase {

  @Override
  public void setUp() throws Exception {
    super.setUp();
  }

  @Ignore
  @Test
  public void testFullCycle() {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2ClientOptions()
        .setFlow(OAuth2FlowType.PASSWORD)
        .setClientID("vertx")
        .setSite("http://localhost:8080/auth/realms/master"),
      res -> {
        if (res.failed()) {
          fail(res.cause());
          return;
        }

        final OAuth2Auth oidc = res.result();

        oidc.authenticate(new JsonObject().put("username", "admin").put("password", "admin"), res1 -> {
          if (res1.failed()) {
            fail(res1.cause().getMessage());
            return;
          }
          AccessToken token = (AccessToken) res1.result();
          assertNotNull(token);
          assertNotNull(token.principal());

          assertNotNull(token.accessToken());
          assertNotNull(token.refreshToken());

          token.userInfo(res2 -> {
            if (res2.failed()) {
              fail(res2.cause().getMessage());
              return;
            }

            assertEquals("admin", res2.result().getString("preferred_username"));

            token.logout(res3 -> {
              if (res3.failed()) {
                fail(res3.cause().getMessage());
                return;
              }

              testComplete();
            });
          });
        });
      });
    await();
  }

  @Ignore
  @Test
  public void testDecode() {
    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2ClientOptions()
        .setClientID("vertx")
        .setSite("http://localhost:8080/auth/realms/master"),
      res -> {
        if (res.failed()) {
          fail(res.cause());
          return;
        }

        final OAuth2Auth oidc = res.result();

        oidc.decodeToken("borked", res1 -> {
          if (res1.failed()) {
            testComplete();
            return;
          }
          fail("Should not reach this!");
        });
      });
    await();
  }
}
