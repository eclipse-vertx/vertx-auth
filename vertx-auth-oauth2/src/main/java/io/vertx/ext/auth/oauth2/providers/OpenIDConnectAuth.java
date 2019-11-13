package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2Response;
import io.vertx.ext.auth.oauth2.impl.OAuth2API;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for OpenID Connect.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the given site in the
   * configuration options and attempt to load the well known descriptor.
   *
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @param vertx the vertx instance
   * @param config the initial config, it should contain a site url
   * @param handler the instantiated Oauth2 provider instance handler
   */
  static void discover(final Vertx vertx, final OAuth2ClientOptions config, final Handler<AsyncResult<OAuth2Auth>> handler) {
    if (config.getSite() == null) {
      handler.handle(Future.failedFuture("issuer cannot be null"));
      return;
    }

    // compute paths with variables, at this moment it is only relevant that
    // the paths and site are properly computed
    config.replaceVariables(false);

    final OAuth2API api = new OAuth2API(vertx, config);
    final HttpClientRequest request = api.makeRequest(HttpMethod.GET, config.getSite() + "/.well-known/openid-configuration", res -> {
      if (res.failed()) {
        handler.handle(Future.failedFuture(res.cause()));
        return;
      }

      final OAuth2Response response = res.result();

      if (response.statusCode() !=  200) {
        handler.handle(Future.failedFuture("Bad Response [" + response.statusCode() + "] " + response.body()));
        return;
      }

      if (!response.is("application/json")) {
        handler.handle(Future.failedFuture("Cannot handle Content-Type: " + response.headers().get("Content-Type")));
        return;
      }

      final JsonObject json = response.jsonObject();

      // issuer validation
      if (config.isValidateIssuer()) {
        final String issuerEndpoint = json.getString("issuer");
        if (issuerEndpoint != null && !config.getSite().equals(issuerEndpoint)) {
          handler.handle(Future.failedFuture("issuer validation failed: received [" + issuerEndpoint + "]"));
          return;
        }
      }

      config.setAuthorizationPath(json.getString("authorization_endpoint"));
      config.setTokenPath(json.getString("token_endpoint"));
      config.setIntrospectionPath(json.getString("token_introspection_endpoint"));
      config.setLogoutPath(json.getString("end_session_endpoint"));
      config.setRevocationPath(json.getString("revocation_endpoint"));
      config.setUserInfoPath(json.getString("userinfo_endpoint"));
      config.setJwkPath(json.getString("jwks_uri"));

      try {
        // the constructor might fail if the configuration is incomplete
        final OAuth2Auth oidc = new OAuth2AuthProviderImpl(api, config);

        if (config.getJwkPath() != null) {
          oidc.loadJWK(v -> {
            if (v.failed()) {
              handler.handle(Future.failedFuture(v.cause()));
              return;
            }

            handler.handle(Future.succeededFuture(oidc));
          });
        } else {
          handler.handle(Future.succeededFuture(oidc));
        }
      } catch (IllegalArgumentException e) {
        handler.handle(Future.failedFuture(e));
      }
    });
    // handle errors
    request.exceptionHandler(t -> handler.handle(Future.failedFuture(t)));
    // we accept JSON as it is the expected response encoding
    request.putHeader("Accept", "application/json");
    // trigger
    request.end();
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery. The discovery will use the given site in the
   * configuration options and attempt to load the well known descriptor.
   *
   * If the discovered config includes a json web key url, it will be also fetched and the JWKs will be loaded
   * into the OAuth provider so tokens can be decoded.
   *
   * @see OpenIDConnectAuth#discover(Vertx, OAuth2ClientOptions, Handler)
   * @param vertx the vertx instance
   * @param config the initial config, it should contain a site url
   * @return future with the instantiated Oauth2 provider instance handler
   */
  static Future<OAuth2Auth> discover(final Vertx vertx, final OAuth2ClientOptions config) {
    Promise<OAuth2Auth> promise = Promise.promise();
    discover(vertx, config, promise);
    return promise.future();
  }
}
