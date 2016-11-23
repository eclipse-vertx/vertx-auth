package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for LinkedIn.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface LinkedInAuth {

  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, String clientId, String clientSecret) {
    return
      OAuth2Auth.create(vertx, flow, new OAuth2ClientOptions()
        .setSite("https://www.linkedin.com")
        .setTokenPath("/uas/oauth2/accessToken")
        .setAuthorizationPath("/uas/oauth2/authorization")
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
