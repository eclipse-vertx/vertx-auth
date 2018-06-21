package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for CloudFoundry UAA.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface CloudFoundryAuth {

  /**
   * Create a OAuth2Auth provider for CloudFoundry UAA
   *
   * @param clientId     the client id given to you by CloudFoundry UAA
   * @param clientSecret the client secret given to you by CloudFoundry UAA
   * @param uuaURL         the url to your UUA server instance
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String uuaURL) {
    return create(vertx, clientId, clientSecret, uuaURL, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for CloudFoundry UAA
   *
   * @param clientId          the client id given to you by CloudFoundry UAA
   * @param clientSecret      the client secret given to you by CloudFoundry UAA
   * @param uuaURL            the url to your UUA server instance
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String uuaURL, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions(httpClientOptions)
        .setSite(uuaURL)
        .setTokenPath("/oauth/token")
        .setAuthorizationPath("/oauth/authorize")
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
