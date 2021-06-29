package io.vertx.ext.auth.otp.totp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.totp.TotpAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.totp.TotpAuthOptions} original class using Vert.x codegen.
 */
public class TotpAuthOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, TotpAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authAttemptsLimit":
          if (member.getValue() instanceof Number) {
            obj.setAuthAttemptsLimit(((Number)member.getValue()).intValue());
          }
          break;
        case "passwordLength":
          if (member.getValue() instanceof Number) {
            obj.setPasswordLength(((Number)member.getValue()).intValue());
          }
          break;
        case "period":
          if (member.getValue() instanceof Number) {
            obj.setPeriod(((Number)member.getValue()).longValue());
          }
          break;
      }
    }
  }

  public static void toJson(TotpAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(TotpAuthOptions obj, java.util.Map<String, Object> json) {
    json.put("authAttemptsLimit", obj.getAuthAttemptsLimit());
    json.put("passwordLength", obj.getPasswordLength());
    json.put("period", obj.getPeriod());
  }
}
