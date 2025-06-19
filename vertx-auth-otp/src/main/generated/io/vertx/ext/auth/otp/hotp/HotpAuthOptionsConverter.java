package io.vertx.ext.auth.otp.hotp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.hotp.HotpAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.hotp.HotpAuthOptions} original class using Vert.x codegen.
 */
public class HotpAuthOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, HotpAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authAttemptsLimit":
          if (member.getValue() instanceof Number) {
            obj.setAuthAttemptsLimit(((Number)member.getValue()).intValue());
          }
          break;
        case "counter":
          if (member.getValue() instanceof Number) {
            obj.setCounter(((Number)member.getValue()).longValue());
          }
          break;
        case "lookAheadWindow":
          if (member.getValue() instanceof Number) {
            obj.setLookAheadWindow(((Number)member.getValue()).intValue());
          }
          break;
        case "passwordLength":
          if (member.getValue() instanceof Number) {
            obj.setPasswordLength(((Number)member.getValue()).intValue());
          }
          break;
      }
    }
  }

   static void toJson(HotpAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(HotpAuthOptions obj, java.util.Map<String, Object> json) {
    json.put("authAttemptsLimit", obj.getAuthAttemptsLimit());
    json.put("counter", obj.getCounter());
    json.put("lookAheadWindow", obj.getLookAheadWindow());
    json.put("passwordLength", obj.getPasswordLength());
  }
}
