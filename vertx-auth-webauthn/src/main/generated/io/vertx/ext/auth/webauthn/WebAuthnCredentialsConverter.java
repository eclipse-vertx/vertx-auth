package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.WebAuthnCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.WebAuthnCredentials} original class using Vert.x codegen.
 */
public class WebAuthnCredentialsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthnCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "challenge":
          if (member.getValue() instanceof String) {
            obj.setChallenge((String)member.getValue());
          }
          break;
        case "domain":
          if (member.getValue() instanceof String) {
            obj.setDomain((String)member.getValue());
          }
          break;
        case "origin":
          if (member.getValue() instanceof String) {
            obj.setOrigin((String)member.getValue());
          }
          break;
        case "username":
          if (member.getValue() instanceof String) {
            obj.setUsername((String)member.getValue());
          }
          break;
        case "webauthn":
          if (member.getValue() instanceof JsonObject) {
            obj.setWebauthn(((JsonObject)member.getValue()).copy());
          }
          break;
        case "userId":
          if (member.getValue() instanceof String) {
            obj.setUserId((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(WebAuthnCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(WebAuthnCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getChallenge() != null) {
      json.put("challenge", obj.getChallenge());
    }
    if (obj.getDomain() != null) {
      json.put("domain", obj.getDomain());
    }
    if (obj.getOrigin() != null) {
      json.put("origin", obj.getOrigin());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
    if (obj.getWebauthn() != null) {
      json.put("webauthn", obj.getWebauthn());
    }
    if (obj.getUserId() != null) {
      json.put("userId", obj.getUserId());
    }
  }
}
