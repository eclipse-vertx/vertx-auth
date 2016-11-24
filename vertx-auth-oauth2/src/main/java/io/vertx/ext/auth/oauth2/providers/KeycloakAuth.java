package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Keycloak.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface KeycloakAuth {

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param config the json config file exported from Keycloak admin console
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config) {
    final OAuth2ClientOptions options = new OAuth2ClientOptions();

    // keycloak conversion to oauth2 options
    if (config.containsKey("auth-server-url")) {
      options.setSite(config.getString("auth-server-url"));
    }

    if (config.containsKey("resource")) {
      options.setClientID(config.getString("resource"));
    }

    if (config.containsKey("credentials") && config.getJsonObject("credentials").containsKey("secret")) {
      options.setClientSecret(config.getJsonObject("credentials").getString("secret"));
    }

    if (config.containsKey("public-client") && config.getBoolean("public-client", false)) {
      options.setUseBasicAuthorizationHeader(true);
    }

    if (config.containsKey("realm")) {
      final String realm = config.getString("realm");

      options.setAuthorizationPath("/realms/" + realm + "/protocol/openid-connect/auth");
      options.setTokenPath("/realms/" + realm + "/protocol/openid-connect/token");
      options.setRevocationPath(null);
      options.setLogoutPath("/realms/" + realm + "/protocol/openid-connect/logout");
      options.setUserInfoPath("/realms/" + realm + "/protocol/openid-connect/userinfo");
    }

    if (config.containsKey("realm-public-key")) {
      options.setPublicKey(config.getString("realm-public-key"));
      options.setJwtToken(true);
    }

    return OAuth2Auth.create(vertx, flow, options);
  }
}
