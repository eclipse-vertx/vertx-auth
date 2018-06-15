package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.URL;

public class OAuth2KeycloakTest extends VertxTestBase {

  private OAuth2Auth oauth2;
  private boolean isKeycloakAvailable;

  // Set the client credentials and the OAuth2 server
  final JsonObject credentials = new JsonObject(
      "{\n" +
      "  \"realm\": \"master\",\n" +
      "  \"auth-server-url\": \"http://localhost:8888/auth\",\n" +
      "  \"ssl-required\": \"external\",\n" +
      "  \"resource\": \"admin-cli\",\n" +
      "  \"public-client\": true,\n" +
      "  \"confidential-port\": 0\n" +
      "}"
  );

  @Override
  public void setUp() throws Exception {
    super.setUp();
    oauth2 = OAuth2Auth.createKeycloak(vertx, OAuth2FlowType.PASSWORD, credentials);

    try {
      URL url = new URL("http://localhost:8888/auth");
      HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
      if (200 == httpConn.getResponseCode()) {
        isKeycloakAvailable = true;
      }
    } catch (Throwable e) {
      System.err.println("!!! Keycloak is not available");
      // assume tests pass as keycloak is not available
      isKeycloakAvailable = false;
    }
  }

  @Test
  public void testFullCycle() {
    if (!isKeycloakAvailable) {
      testComplete();
      return;
    }
    oauth2.authenticate(new JsonObject().put("username", "user").put("password", "password"), res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        AccessToken token = (AccessToken) res.result();
        assertNotNull(token);
        assertNotNull(token.principal());

        token.setTrustJWT(true);

        token.isAuthorized("email", r -> {
          assertTrue(r.result());

          token.refresh(res2 -> {
            if(res2.failed()) {
              fail(res2.cause().getMessage());
            } else {
              assertNotNull(token.principal());

              // logout
              token.logout(res3 -> {
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
  public void testLogout() {
    if (!isKeycloakAvailable) {
      testComplete();
      return;
    }
    oauth2.authenticate(new JsonObject().put("username", "user").put("password", "password"), res -> {
      if (res.failed()) {
        fail(res.cause().getMessage());
      } else {
        AccessToken token = (AccessToken) res.result();
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

  @Test
  public void testDecodeShouldFail() throws Exception {
    super.setUp();
    if (!isKeycloakAvailable) {
      testComplete();
      return;
    }
    oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.AUTH_CODE, credentials);
    oauth2.decodeToken("borked", res1 -> {
      if (res1.failed()) {
        testComplete();
        return;
      }
      fail("Should not reach this!");
    });

    await();
  }

  @Test
  public void testDecodeShouldPass() throws Exception {
    super.setUp();
    if (!isKeycloakAvailable) {
      testComplete();
      return;
    }
    oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.PASSWORD, credentials);

    oauth2.loadJWK(v -> {
      if (v.failed()) {
        fail(v.cause().getMessage());
      } else {
        oauth2.authenticate(new JsonObject().put("username", "user").put("password", "password"), res -> {
          if (res.failed()) {
            fail(res.cause().getMessage());
          } else {
            AccessToken token = (AccessToken) res.result();
            assertNotNull(token);
            assertNotNull(token.principal());

            oauth2.decodeToken(token.opaqueAccessToken(), res1 -> {
              if (res1.succeeded()) {
                testComplete();
                return;
              }
              fail("Should not reach this!");
            });
          }
        });
      }
    });

    await();
  }
}
