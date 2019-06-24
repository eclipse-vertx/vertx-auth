package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for live.com Services.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface LiveAuth {

  /**
   * Create a OAuth2Auth provider for live.com
   *
   * @param clientId     the client id given to you by live.com
   * @param clientSecret the client secret given to you by live.com
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for live.com
   *
   * @param clientId          the client id given to you by live.com
   * @param clientSecret      the client secret given to you by live.com
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2ClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setSite("https://login.live.com")
        .setTokenPath("/oauth20_token.srf")
        .setAuthorizationPath("/oauth20_authorize.srf")
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
