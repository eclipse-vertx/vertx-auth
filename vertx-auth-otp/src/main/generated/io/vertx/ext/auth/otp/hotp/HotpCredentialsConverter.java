package io.vertx.ext.auth.otp.hotp;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.otp.hotp.HotpCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.otp.hotp.HotpCredentials} original class using Vert.x codegen.
 */
public class HotpCredentialsConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, HotpCredentials obj) {
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

   static void toJson(HotpCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(HotpCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getCode() != null) {
      json.put("code", obj.getCode());
    }
    if (obj.getIdentifier() != null) {
      json.put("identifier", obj.getIdentifier());
    }
  }
}
