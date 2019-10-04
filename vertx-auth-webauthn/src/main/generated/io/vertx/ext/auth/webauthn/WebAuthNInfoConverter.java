package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.WebAuthNInfo}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.WebAuthNInfo} original class using Vert.x codegen.
 */
public class WebAuthNInfoConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthNInfo obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "challenge":
          if (member.getValue() instanceof String) {
            obj.setChallenge((String)member.getValue());
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
      }
    }
  }

  public static void toJson(WebAuthNInfo obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(WebAuthNInfo obj, java.util.Map<String, Object> json) {
    if (obj.getChallenge() != null) {
      json.put("challenge", obj.getChallenge());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
    if (obj.getWebauthn() != null) {
      json.put("webauthn", obj.getWebauthn());
    }
  }
}
