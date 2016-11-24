package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Mailchimp.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface MailchimpAuth {

  /**
   * Create a OAuth2Auth provider for Dropbox
   *
   * @param clientId the client id given to you by Mailchimp
   * @param clientSecret the client secret given to you by Mailchimp
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
        .setSite("https://login.mailchimp.com")
        .setTokenPath("/oauth2/token")
        .setAuthorizationPath("/oauth2/authorize")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
