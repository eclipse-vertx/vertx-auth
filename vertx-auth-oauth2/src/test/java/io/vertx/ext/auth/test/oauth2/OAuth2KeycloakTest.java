package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

public class OAuth2KeycloakTest extends VertxTestBase {

  private OAuth2Auth oauth2;

  // Set the client credentials and the OAuth2 server
  final KeycloakClientOptions credentials = new KeycloakClientOptions(new JsonObject(
      "{\n" +
          "  \"realm\": \"master\",\n" +
          "  \"realm-public-key\": \"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGQkaBkiZWpUjFOuaabgfXgjzZzfJd0wozrS1czX5qHNKG3P79P/UtZeR3wGN8r15jVYiH42GMINMs7R7iP5Mbm1iImge5p/7/dPmXirKOKOBhjA3hNTiV5BlPDTQyiuuTAUEms5dY4+moswXo5zM4q9DFu6B7979o+v3kX6ZB+k3kNhP08wH82I4eJKoenN/0iCT7ALoG3ysEJf18+HEysSnniLMJr8R1pYF2QRFlqaDv3Mqyp7ipxYkt4ebMCgE7aDzT6OrfpyPowObpdjSMTUXpcwIcH8mIZCWFmyfF675zEeE0e+dHKkL1rPeCI7rr7Bqc5+1DS5YM54fk8xQwIDAQAB\",\n" +
          "  \"auth-server-url\": \"http://localhost:9000/auth\",\n" +
          "  \"ssl-required\": \"external\",\n" +
          "  \"resource\": \"frontend\",\n" +
          "  \"credentials\": {\n" +
          "    \"secret\": \"2fbf5e18-b923-4a83-9657-b4ebd5317f60\"\n" +
          "  }\n" +
          "}"
  ));

  @Override
  public void setUp() throws Exception {
    super.setUp();

    oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.PASSWORD, credentials);
  }

  @Test
  @Ignore
  public void testFullCycle() {
    oauth2.getToken(new JsonObject().put("username", "pmlopes").put("password", "password"), res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        AccessToken token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());

        token.isAuthorised("account:manage-account", r -> {
          assertTrue(r.result());

          token.refresh(res2 -> {
            if(res2.failed()) {
              fail(res2.cause().getMessage());
            } else {
              assertNotNull(token.principal());

              // logout
              oauth2.api(HttpMethod.GET, credentials.getLogoutPath(), new JsonObject().put("access_token", token.principal().getString("access_token")), res3 -> {
                if(res3.failed()) {
                  fail(res3.cause().getMessage());
                } else {
                  System.out.println(res3.result());
                  testComplete();
                }
              });
            }
          });
        });
      }
    });
    await();
  }

  @Test
  @Ignore
  public void testLogout() {
    oauth2.getToken(new JsonObject().put("username", "pmlopes").put("password", "password"), res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        AccessToken token = res.result();
        assertNotNull(token);
        assertNotNull(token.principal());

        // go to keycloak web interface, there should be 1 session

        vertx.setTimer(10000, v -> {
          // logout
          token.logout(res3 -> {
            if(res3.failed()) {
              fail(res3.cause().getMessage());
            } else {

              // go to keycloak web interface, there should be no session
              testComplete();
            }
          });
        });
      }
    });
    await();
  }
}
