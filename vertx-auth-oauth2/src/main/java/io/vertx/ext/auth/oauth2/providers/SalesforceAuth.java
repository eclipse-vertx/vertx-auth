package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
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
public interface SalesforceAuth extends OpenIDConnectAuth {

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
      OAuth2Auth.create(vertx, new OAuth2ClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setSite("http://login.salesforce.com")
        .setTokenPath("/services/oauth2/token")
        .setAuthorizationPath("/services/oauth2/authorize")
        .setScopeSeparator("+")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx   the vertx instance
   * @param config  the initial config
   * @param handler the instantiated Oauth2 provider instance handler
   */
  static void discover(final Vertx vertx, final OAuth2ClientOptions config, final Handler<AsyncResult<OAuth2Auth>> handler) {
    // don't override if already set
    final String site = config.getSite() == null ? "https://login.salesforce.com" : config.getSite();

    OpenIDConnectAuth.discover(vertx,
      new OAuth2ClientOptions(config)
        .setSite("https://login.salesforce.com")
        .setScopeSeparator("+"),
      handler);
  }
}
