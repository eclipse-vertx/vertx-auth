package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.auth.oauth2.OAuth2Response;

import static io.vertx.ext.auth.oauth2.impl.OAuth2API.*;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for OpenID Connect.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface OpenIDConnectAuth {

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery.
   *
   */
  static void create(Vertx vertx, String clientId, String baseUrl, Handler<AsyncResult<OAuth2Auth>> handler) {
    create(vertx, OAuth2FlowType.AUTH_CODE, clientId, null, baseUrl, new HttpClientOptions(), handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery.
   *
   */
  static void createWithFlow(Vertx vertx, OAuth2FlowType flow, String clientId, String baseUrl, Handler<AsyncResult<OAuth2Auth>> handler) {
    create(vertx, flow, clientId, null, baseUrl, new HttpClientOptions(), handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery.
   *
   */
  static void create(Vertx vertx, String clientId, String clientSecret, String baseUrl, Handler<AsyncResult<OAuth2Auth>> handler) {
    create(vertx, OAuth2FlowType.AUTH_CODE, clientId, clientSecret, baseUrl, new HttpClientOptions(), handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery.
   *
   */
  static void createWithFlow(Vertx vertx, OAuth2FlowType flow, String clientId, String clientSecret, String baseUrl, Handler<AsyncResult<OAuth2Auth>> handler) {
    create(vertx, flow, clientId, clientSecret, baseUrl, new HttpClientOptions(), handler);
  }

  /**
   * Create a OAuth2Auth provider for OpenID Connect Discovery.
   *
   */
  static void create(Vertx vertx, OAuth2FlowType flow, String clientId, String clientSecret, String issuer, HttpClientOptions options, Handler<AsyncResult<OAuth2Auth>> handler) {
    if (issuer == null) {
      handler.handle(Future.failedFuture("issuer cannot be null"));
      return;
    }

    final HttpClientRequest request = makeRequest(vertx, options, HttpMethod.GET, issuer + "/.well-known/openid-configuration", res -> {
      if (res.failed()) {
        handler.handle(Future.failedFuture(res.cause()));
        return;
      }

      final OAuth2Response response = res.result();

      if (!response.is("application/json")) {
        handler.handle(Future.failedFuture("Cannot handle Content-Type: " + response.headers().get("Content-Type")));
        return;
      }

      final JsonObject json = response.jsonObject();

      final OAuth2ClientOptions config = new OAuth2ClientOptions(options);

      config.setClientID(clientId);
      config.setClientSecret(clientSecret);

      // issuer validation
      final String issuerEndpoint = json.getString("issuer");
      if (issuerEndpoint != null && !issuer.equals(issuerEndpoint)) {
        handler.handle(Future.failedFuture("issuer validation failed: received [" + issuerEndpoint + "]"));
        return;
      }

      config.setAuthorizationPath(json.getString("authorization_endpoint"));
      config.setTokenPath(json.getString("token_endpoint"));
      config.setIntrospectionPath(json.getString("token_introspection_endpoint"));
      config.setLogoutPath(json.getString("end_session_endpoint"));
      config.setRevocationPath(json.getString("revocation_endpoint"));
      config.setUserInfoPath(json.getString("userinfo_endpoint"));
      config.setJwkPath(json.getString("jwks_uri"));
      config.setOpenIdConnect(true);

      final OAuth2Auth oidc = OAuth2Auth.create(vertx, flow, config);

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
    });
    // handle errors
    request.exceptionHandler(t -> handler.handle(Future.failedFuture(t)));
    // we accept JSON as it is the expected response encoding
    request.putHeader("Accept", "application/json");
    // trigger
    request.end();
  }
}
