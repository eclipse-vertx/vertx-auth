package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Salesforce.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface SalesforceAuth {

  /**
   * Create a OAuth2Auth provider for Salesforce
   *
   * @param clientId     the client id given to you by Salesforce
   * @param clientSecret the client secret given to you by Salesforce
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Salesforce
   *
   * @param clientId          the client id given to you by Salesforce
   * @param clientSecret      the client secret given to you by Salesforce
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions(httpClientOptions)
        .setSite("http://login.salesforce.com")
        .setTokenPath("/services/oauth2/token")
        .setAuthorizationPath("/services/oauth2/authorize")
        .setScopeSeparator("+")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
