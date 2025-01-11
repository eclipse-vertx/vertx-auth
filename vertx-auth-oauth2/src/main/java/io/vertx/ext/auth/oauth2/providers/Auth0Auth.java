package io.vertx.ext.auth.oauth2.providers;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Okta Auth0.
 *
 * @author <a href="mailto:alexei.klenin@gmail.com">Alexei KLENIN</a>
 */
public interface Auth0Auth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Okta Auth0
   *
   * @param clientId     the client id given to you by Okta Auth0
   * @param clientSecret the client secret given to you by Okta Auth0
   * @param tenant       the tenant
   * @param audience     the audience
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String tenant, String audience) {
    return create(vertx, clientId, clientSecret, tenant, audience, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Okta Auth0
   *
   * @param clientId          the client id given to you by Okta Auth0
   * @param clientSecret      the client secret given to you by Okta Auth0
   * @param tenant            the tenant
   * @param audience          the audience
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(
      Vertx vertx,
      String clientId,
      String clientSecret,
      String tenant,
      String audience,
      HttpClientOptions httpClientOptions) {
    if (audience == null || audience.isEmpty()) {
      throw new IllegalArgumentException("audience cannot be null or empty");
    }

    String site = "https://{tenant}.auth0.com";

    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setTenant(tenant)
        .setSite(site)
        .setTokenPath(site + "/oauth/token")
        .setAuthorizationPath(site + "/authorize")
        .setUserInfoPath(site + "/userInfo")
        .setRevocationPath(site + "/oauth/revoke")
        .setJwkPath(site + "/.well-known/jwks.json")
        .setScopeSeparator(" ")
        .setJWTOptions(new JWTOptions())
        .setExtraParameters(new JsonObject().put("audience", audience)));
  }
}
