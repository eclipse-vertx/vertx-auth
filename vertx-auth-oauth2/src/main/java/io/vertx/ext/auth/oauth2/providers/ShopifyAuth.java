package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for Shopify.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface ShopifyAuth {

  /**
   * Create a OAuth2Auth provider for Shopify
   *
   * @param clientId     the client id given to you by Shopify
   * @param clientSecret the client secret given to you by Shopify
   * @param shop         your shop name
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String shop) {
    return create(vertx, clientId, clientSecret, shop, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Shopify
   *
   * @param clientId          the client id given to you by Shopify
   * @param clientSecret      the client secret given to you by Shopify
   * @param shop              your shop name
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, String shop, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, new OAuth2ClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setSite("https://" + shop + ".myshopify.com")
        .setTokenPath("/admin/oauth/access_token")
        .setAuthorizationPath("/admin/oauth/authorize")
        .setUserInfoPath("/admin/shop.json")
        .setScopeSeparator(",")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }
}
