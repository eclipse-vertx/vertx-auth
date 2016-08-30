package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.json.JsonObject;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Helper class for processing Keycloak principal.
 *
 * @author Eric Zhao
 */
@VertxGen
public interface KeycloakHelper {

  /**
   * Get raw `id_token` string from the principal.
   *
   * @param principal user principal
   * @return the raw id token string
   */
  static String rawIdToken(JsonObject principal) {
    return principal.getString("id_token");
  }

  /**
   * Get decoded `id_token` from the principal.
   *
   * @param principal user principal
   * @return the id token
   */
  static JsonObject idToken(JsonObject principal) {
    return parseToken(rawIdToken(principal));
  }

  /**
   * Get raw `access_token` string from the principal.
   *
   * @param principal user principal
   * @return the raw access token string
   */
  static String rawAccessToken(JsonObject principal) {
    return principal.getString("access_token");
  }

  /**
   * Get decoded `access_token` from the principal.
   *
   * @param principal user principal
   * @return the access token
   */
  static JsonObject accessToken(JsonObject principal) {
    return parseToken(rawAccessToken(principal));
  }

  // helper methods for getting fields from the principal

  static int authTime(JsonObject principal) {
    return idToken(principal).getInteger("auth_time");
  }

  static String sessionState(JsonObject principal) {
    return idToken(principal).getString("session_state");
  }

  static String acr(JsonObject principal) {
    return idToken(principal).getString("acr");
  }

  static String name(JsonObject principal) {
    return idToken(principal).getString("name");
  }

  static String email(JsonObject principal) {
    return idToken(principal).getString("email");
  }

  static String preferredUsername(JsonObject principal) {
    return idToken(principal).getString("preferred_username");
  }

  static String nickName(JsonObject principal) {
    return idToken(principal).getString("nickname");
  }

  @SuppressWarnings("unchecked")
  static Set<String> allowedOrigins(JsonObject principal) {
    List<String> allowedOrigins = accessToken(principal)
      .getJsonArray("allowed-origins")
      .getList();
    return new HashSet<>(allowedOrigins);
  }

  /**
   * Parse the token string with base64 decoder.
   * This will only obtain the "payload" part of the token.
   *
   * @param token token string
   * @return token payload json object
   */
  static JsonObject parseToken(String token) {
    if (token == null) {
      return null;
    }
    String[] parts = token.split("\\.");
    if (parts.length < 2 || parts.length > 3) {
      throw new IllegalArgumentException("Parsing error");
    }
    try {
      String decoded = new String(Base64.getDecoder().decode(parts[1]), "UTF-8");
      return new JsonObject(decoded); // get "payload" part
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}
