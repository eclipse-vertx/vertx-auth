package io.vertx.ext.auth.otp.totp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.totp.TotpAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.totp.TotpAuthOptions} original class using Vert.x codegen.
 */
public class TotpAuthOptionsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, TotpAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "passwordLength":
          if (member.getValue() instanceof Number) {
            obj.setPasswordLength(((Number)member.getValue()).intValue());
          }
          break;
        case "authAttemptsLimit":
          if (member.getValue() instanceof Number) {
            obj.setAuthAttemptsLimit(((Number)member.getValue()).intValue());
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

   static void toJson(TotpAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(TotpAuthOptions obj, java.util.Map<String, Object> json) {
    json.put("passwordLength", obj.getPasswordLength());
    json.put("authAttemptsLimit", obj.getAuthAttemptsLimit());
    json.put("period", obj.getPeriod());
  }
}
