package io.vertx.ext.auth.oauth2.providers;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;

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
   * @param clientId the client id given to you by Google
   * @param clientSecret the client secret given to you by Google
   */
  static OAuth2Auth create(Vertx vertx, String clientId, String clientSecret) {
    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
        .setSite("https://accounts.google.com")
        .setTokenPath("https://www.googleapis.com/oauth2/v3/token")
        .setAuthorizationPath("/o/oauth2/auth")
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
    final StringBuilder privateKey = new StringBuilder();
    for (String s : serviceAccountJson.getString("private_key").split("\n")) {
      if ("-----BEGIN PRIVATE KEY-----".equals(s) || "-----END PRIVATE KEY-----".equals(s)) {
        continue;
      }
      privateKey.append(s);
    }

    return
      OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_JWT, new OAuth2ClientOptions()
        .setSite("https://accounts.google.com")
        .setTokenPath(serviceAccountJson.getString("token_uri"))
        .setPrivateKey(privateKey.toString())
        .setExtraParameters(new JsonObject()
          .put("algorithm", "RS256")
          .put("expiresInMinutes", 60)
          .put("audience", "https://www.googleapis.com/oauth2/v4/token")
          .put("issuer", serviceAccountJson.getString("client_email"))));
  }
}
