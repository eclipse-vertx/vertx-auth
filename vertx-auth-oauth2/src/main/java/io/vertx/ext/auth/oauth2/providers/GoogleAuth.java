package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.jwt.JWTOptions;

/**
 * Simplified factory to create an {@link io.vertx.ext.auth.oauth2.OAuth2Auth} for Google.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@VertxGen
public interface GoogleAuth {

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId     the client id given to you by Google
   * @param clientSecret the client secret given to you by Google
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return create(vertx, clientId, clientSecret, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google
   *
   * @param clientId          the client id given to you by Google
   * @param clientSecret      the client secret given to you by Google
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret, HttpClientOptions httpClientOptions) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions(httpClientOptions)
        .setSite("https://accounts.google.com")
        .setTokenPath("https://www.googleapis.com/oauth2/v3/token")
        .setAuthorizationPath("/o/oauth2/auth")
        .setIntrospectionPath("https://www.googleapis.com/oauth2/v3/tokeninfo")
        .setUserInfoPath("https://www.googleapis.com/oauth2/v3/userinfo")
        .setJwkPath("https://www.googleapis.com/oauth2/v3/certs")
        .setUserInfoParameters(new JsonObject()
          .put("alt", "json"))
        .setScopeSeparator(" ")
        .setClientID(clientId)
        .setClientSecret(clientSecret));
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson) {
    return create(vertx, serviceAccountJson, new HttpClientOptions());
  }

  /**
   * Create a OAuth2Auth provider for Google Service Account (Server to Server)
   *
   * @param serviceAccountJson the configuration json file from your Google API page
   * @param httpClientOptions custom http client options
   */
  static OAuth2Auth create(Vertx vertx, JsonObject serviceAccountJson, HttpClientOptions httpClientOptions) {
    final StringBuilder privateKey = new StringBuilder();
    for (String s : serviceAccountJson.getString("private_key").split("\n")) {
      if ("-----BEGIN PRIVATE KEY-----".equals(s) || "-----END PRIVATE KEY-----".equals(s)) {
        continue;
      }
      privateKey.append(s);
    }

    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_JWT, new OAuth2ClientOptions(httpClientOptions)
        .setSite("https://accounts.google.com")
        .setTokenPath(serviceAccountJson.getString("token_uri"))
        .addPubSecKey(new PubSecKeyOptions()
          .setAlgorithm("RS256")
          .setSecretKey(privateKey.toString()))
        .setJWTToken(true)
        .setJWTOptions(new JWTOptions()
          .setAlgorithm("RS256")
          .setExpiresInMinutes(60)
          .addAudience("https://www.googleapis.com/oauth2/v4/token")
          .setIssuer(serviceAccountJson.getString("client_email"))));
  }
}
