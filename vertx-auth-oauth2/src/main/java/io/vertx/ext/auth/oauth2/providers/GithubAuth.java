package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Github.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface GithubAuth {

  /**
   * Create a OAuth2Auth provider for Github
   *
   * @param clientId the client id given to you by Github
   * @param clientSecret the client secret given to you by Github
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Github
   *
   * @param clientId the client id given to you by Github
   * @param clientSecret the client secret given to you by Github
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2ClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setSite("https://github.com/login")
        .setTokenPath("/oauth/access_token")
        .setAuthorizationPath("/oauth/authorize")
        .setUserInfoPath("https://api.github.com/user")
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret)
        .setHeaders(new JsonObject()
          .put("User-Agent", "vertx-auth-oauth2")));
  }
}
