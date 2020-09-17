package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.Authenticator}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.Authenticator} original class using Vert.x codegen.
 */
public class AuthenticatorConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, Authenticator obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "counter":
          if (member.getValue() instanceof Number) {
            obj.setCounter(((Number)member.getValue()).longValue());
          }
          break;
        case "credID":
          if (member.getValue() instanceof String) {
            obj.setCredID((String)member.getValue());
          }
          break;
        case "publicKey":
          if (member.getValue() instanceof String) {
            obj.setPublicKey((String)member.getValue());
          }
          break;
        case "type":
          if (member.getValue() instanceof String) {
            obj.setType((String)member.getValue());
          }
          break;
        case "userName":
          if (member.getValue() instanceof String) {
            obj.setUserName((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(Authenticator obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(Authenticator obj, java.util.Map<String, Object> json) {
    json.put("counter", obj.getCounter());
    if (obj.getCredID() != null) {
      json.put("credID", obj.getCredID());
    }
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
    if (obj.getUserName() != null) {
      json.put("userName", obj.getUserName());
    }
  }
}
