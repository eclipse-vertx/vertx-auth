package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Azure AD.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface AzureADAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for Microsoft Azure Active Directory
   *
   * @param clientId     the client id given to you by Azure
   * @param clientSecret the client secret given to you by Azure
   * @param guid         the guid of your application given to you by Azure
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String guid) {
    return create(vertx, clientId, clientSecret, guid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Microsoft Azure Active Directory
   *
   * @param clientId          the client id given to you by Azure
   * @param clientSecret      the client secret given to you by Azure
   * @param guid              the guid of your application given to you by Azure
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String guid, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2ClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setSite("https://login.windows.net/" + guid)
        .setTokenPath("/oauth2/token")
        .setAuthorizationPath("/oauth2/authorize")
        .setScopeSeparator(",")
        .setClientID(clientId)
        .setClientSecret(clientSecret)
        .setExtraParameters(
          new JsonObject().put("resource", guid)));
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
    final String site = config.getSite() == null ? "https://login.windows.net/common" : config.getSite();

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2ClientOptions(config)
        // Azure OpenId does not return the same url where the request was sent to
        .setValidateIssuer(false)
        .setSite(site)
        .setScopeSeparator(","),
      handler);
  }
}
