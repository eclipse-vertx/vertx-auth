package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Dropbox.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface FoursquareAuth {

  /**
   * Create a OAuth2Auth provider for Dropbox
   *
   * @param clientId the client id given to you by Dropbox
   * @param clientSecret the client secret given to you by Dropbox
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
        .setSite("https://foursquare.com")
        .setTokenPath("/oauth2/access_token")
        .setAuthorizationPath("/oauth2/authenticate")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
