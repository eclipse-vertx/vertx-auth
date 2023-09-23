package io.vertx.ext.auth.otp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.Authenticator}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.Authenticator} original class using Vert.x codegen.
 */
public class AuthenticatorConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, Authenticator obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "identifier":
          if (member.getValue() instanceof String) {
            obj.setIdentifier((String)member.getValue());
          }
          break;
        case "key":
          if (member.getValue() instanceof String) {
            obj.setKey((String)member.getValue());
          }
          break;
        case "algorithm":
          if (member.getValue() instanceof String) {
            obj.setAlgorithm((String)member.getValue());
          }
          break;
        case "counter":
          if (member.getValue() instanceof Number) {
            obj.setCounter(((Number)member.getValue()).longValue());
          }
          break;
        case "period":
          if (member.getValue() instanceof Number) {
            obj.setPeriod(((Number)member.getValue()).longValue());
          }
          break;
        case "authAttempts":
          if (member.getValue() instanceof Number) {
            obj.setAuthAttempts(((Number)member.getValue()).intValue());
          }
          break;
      }
    }
  }

  public static void toJson(Authenticator obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(Authenticator obj, java.util.Map<String, Object> json) {
    if (obj.getIdentifier() != null) {
      json.put("identifier", obj.getIdentifier());
    }
    if (obj.getKey() != null) {
      json.put("key", obj.getKey());
    }
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    json.put("counter", obj.getCounter());
    json.put("period", obj.getPeriod());
    if (obj.getAuthAttempts() != null) {
      json.put("authAttempts", obj.getAuthAttempts());
    }
  }
}
