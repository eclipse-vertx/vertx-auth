package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Twitter.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface TwitterAuth {

  /**
   * Create a OAuth2Auth provider for Twitter
   *
   * @param clientId the client id given to you by Twitter
   * @param clientSecret the client secret given to you by Twitter
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
        .setSite("https://api.twitter.com")
        .setTokenPath("/oauth/access_token")
        .setAuthorizationPath("/oauth/authorize")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
