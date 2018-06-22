package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;

@VertxGen
public interface OAuth2User extends User {

  /**
   * The Access Token if present parsed as a JsonObject
   * @return JSON
   */
  JsonObject accessToken();

  /**
   * The Refresh Token if present parsed as a JsonObject
   * @return JSON
   */
  JsonObject refreshToken();

  /**
   * The Id Token if present parsed as a JsonObject
   * @return JSON
   */
  JsonObject idToken();

  /**
   * The RAW String if available for the Access Token
   * @return String
   */
  String opaqueAccessToken();

  /**
   * The RAW String if available for the Refresh Token
   * @return String
   */
  String opaqueRefreshToken();

  /**
   * The RAW String if available for the Id Token
   * @return String
   */
  String opaqueIdToken();
}
