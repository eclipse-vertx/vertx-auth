package io.vertx.tests;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(VertxUnitRunner.class)
public class KeycloakFromJsonTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testCreateFromJson() {
    JsonObject keycloakJson = new JsonObject()
      .put("realm", "master")
      .put("realm-public-key", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGQkaBkiZWpUjFOuaabgfXgjzZzfJd0wozrS1czX5qHNKG3P79P/UtZeR3wGN8r15jVYiH42GMINMs7R7iP5Mbm1iImge5p/7/dPmXirKOKOBhjA3hNTiV5BlPDTQyiuuTAUEms5dY4+moswXo5zM4q9DFu6B7979o+v3kX6ZB+k3kNhP08wH82I4eJKoenN/0iCT7ALoG3ysEJf18+HEysSnniLMJr8R1pYF2QRFlqaDv3Mqyp7ipxYkt4ebMCgE7aDzT6OrfpyPowObpdjSMTUXpcwIcH8mIZCWFmyfF675zEeE0e+dHKkL1rPeCI7rr7Bqc5+1DS5YM54fk8xQwIDAQAB")
      .put("auth-server-url", "http://localhost:9000/auth")
      .put("ssl-required", "external")
      .put("resource", "frontend")
      .put("credentials", new JsonObject()
        .put("secret", "2fbf5e18-b923-4a83-9657-b4ebd5317f60"));

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = KeycloakAuth
      .create(rule.vertx(), OAuth2FlowType.PASSWORD, keycloakJson);
  }
}
