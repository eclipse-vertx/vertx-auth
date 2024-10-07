package io.vertx.ext.auth.otp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.OtpCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.OtpCredentials} original class using Vert.x codegen.
 */
public class OtpCredentialsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, OtpCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "code":
          if (member.getValue() instanceof String) {
            obj.setCode((String)member.getValue());
          }
          break;
        case "identifier":
          if (member.getValue() instanceof String) {
            obj.setIdentifier((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(OtpCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(OtpCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getCode() != null) {
      json.put("code", obj.getCode());
    }
    if (obj.getIdentifier() != null) {
      json.put("identifier", obj.getIdentifier());
    }
  }
}
