package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Options;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

/**
 * Simplified factory to create an {@link OAuth2Auth} for IBM Cloud.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface IBMCloudAuth extends OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for IBM Cloud
   *
   * @param region       the region to use
   * @param clientId     the client id given to you by IBM Cloud
   * @param clientSecret the client secret given to you by IBM Cloud
   * @param guid         the guid of your application given to you by IBM Cloud
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String guid) {
    return create(vertx, region, clientId, clientSecret, guid, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for IBM Cloud
   *
   * @param region            the region to use
   * @param clientId          the client id given to you by IBM Cloud
   * @param clientSecret      the client secret given to you by IBM Cloud
   * @param guid              the guid of your application given to you by IBM Cloud
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String region, String clientId, String clientSecret, String guid, HttpClientOptions httpClientOptions) {
    if (region == null) {
      throw new IllegalStateException("region cannot be null");
    }

    return
      OAuth2Auth.create(vertx, new OAuth2Options()
        .setHttpClientOptions(httpClientOptions)
        .setFlow(OAuth2FlowType.AUTH_CODE)
        .setClientID(clientId)
        .setClientSecret(clientSecret)
        .setTenant(guid)
        .setSite("https://" + region + ".appid.cloud.ibm.com/oauth/v4/{tenant}")
        .setTokenPath("/token")
        .setAuthorizationPath("/authorization")
        .setJwkPath("/publickeys")
        .setUserInfoPath("/userinfo"));
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
  static void discover(final Vertx vertx, final OAuth2Options config, final Handler<AsyncResult<OAuth2Auth>> handler) {
    OpenIDConnectAuth.discover(vertx, config, handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the default site in the
   * configuration options and attempt to load the well known descriptor. If a site is provided (for example when
   * running on a custom instance) that site will be used to do the lookup.
   * <p>
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @see IBMCloudAuth#discover(Vertx, OAuth2Options, Handler)
   * @param vertx   the vertx instance
   * @param config  the initial config
   * @return future with instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2Options config) {
    Promise<OAuth2Auth> promise = Promise.promise();
    discover(vertx, config, promise);
    return promise.future();
  }
}
