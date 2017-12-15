package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
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
  static OAuth2Auth create(Vertx vertx, JsonObject config) {
    return create(vertx, OAuth2FlowType.AUTH_CODE, config);
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param flow   the oauth2 flow to use
   * @param config the json config file exported from Keycloak admin console
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config) {
    return create(vertx, flow, config, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param config            the json config file exported from Keycloak admin console
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, JsonObject config, HttpClientOptions httpClientOptions) {
    return create(vertx, OAuth2FlowType.AUTH_CODE, config, httpClientOptions);
  }

  /**
   * Create a OAuth2Auth provider for Keycloak
   *
   * @param flow              the oauth2 flow to use
   * @param config            the json config file exported from Keycloak admin console
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, JsonObject config, HttpClientOptions httpClientOptions) {
    final OAuth2ClientOptions options = new OAuth2ClientOptions(httpClientOptions);

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
      // keycloak follows the RFC7662
      options.setIntrospectionPath("/realms/" + realm + "/protocol/openid-connect/token/introspect");
      // keycloak follows the RFC7517
      options.setJwkPath("/realms/" + realm + "/protocol/openid-connect/certs");
    }

    if (config.containsKey("realm-public-key")) {
      options.addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setPublicKey(config.getString("realm-public-key")));
      // we could load keys
      options.setJWTToken(true);
    }

    return OAuth2Auth.create(vertx, flow, options);
  }
}
