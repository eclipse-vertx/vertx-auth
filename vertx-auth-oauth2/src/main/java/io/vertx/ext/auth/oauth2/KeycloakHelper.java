package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import sun.misc.BASE64Decoder;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Helper class for processing Keycloak principal.
 *
 * @author Eric Zhao
 */
public final class KeycloakHelper {

  private KeycloakHelper() {
  }

  /**
   * Get raw `id_token` string from the principal.
   *
   * @param principal user principal
   * @return the raw id token string
   */
  public static String getRawIdToken(JsonObject principal) {
    return principal.getString("id_token");
  }

  /**
   * Get decoded `id_token` from the principal.
   *
   * @param principal user principal
   * @return the id token
   */
  public static JsonObject getIdToken(JsonObject principal) {
    return parseToken(getRawIdToken(principal));
  }

  /**
   * Get raw `access_token` string from the principal.
   *
   * @param principal user principal
   * @return the raw access token string
   */
  public static String getRawAccessToken(JsonObject principal) {
    return principal.getString("access_token");
  }

  /**
   * Get decoded `access_token` from the principal.
   *
   * @param principal user principal
   * @return the access token
   */
  public static JsonObject getAccessToken(JsonObject principal) {
    return parseToken(getRawAccessToken(principal));
  }

  // helper methods for getting fields from the principal

  public static int getAuthTime(JsonObject principal) {
    return getIdToken(principal).getInteger("auth_time");
  }

  public static String getSessionState(JsonObject principal) {
    return getIdToken(principal).getString("session_state");
  }

  public static String getAcr(JsonObject principal) {
    return getIdToken(principal).getString("acr");
  }

  public static String getName(JsonObject principal) {
    return getIdToken(principal).getString("name");
  }

  public static String getEmail(JsonObject principal) {
    return getIdToken(principal).getString("email");
  }

  public static String getPreferredUsername(JsonObject principal) {
    return getIdToken(principal).getString("preferred_username");
  }

  public static String getNickName(JsonObject principal) {
    return getIdToken(principal).getString("nickname");
  }

  @SuppressWarnings("unchecked")
  public static Set<String> getAllowedOrigins(JsonObject principal) {
    List<String> allowedOrigins = getAccessToken(principal)
      .getJsonArray("allowed-origins")
      .getList();
    return new HashSet<>(allowedOrigins);
  }

  /**
   * Parse the token string with base64 encoder.
   * This will only obtain the "payload" part of the token.
   *
   * @param token token string
   * @return token payload json object
   */
  public static JsonObject parseToken(String token) {
    if (token == null) {
      return null;
    }
    String[] parts = token.split("\\.");
    if (parts.length < 2 || parts.length > 3) {
      throw new IllegalArgumentException("Parsing error");
    }
    return new JsonObject(decodeBase64(parts[1])); // get "payload" part
  }

  private static String decodeBase64(String s) {
    String decoded = null;
    if (s != null) {
      s = s.replace('-', '+');
      s = s.replace('_', '/');
      switch (s.length() % 4) { // need padding
        case 0:
          break;
        case 2:
          s += "==";
          break;
        case 3:
          s += "=";
          break;
        default:
          throw new RuntimeException("Illegal string");
      }
      BASE64Decoder decoder = new BASE64Decoder();
      try {
        byte[] b = decoder.decodeBuffer(s);
        decoded = new String(b, "UTF-8");
      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }
    return decoded;
  }
}
