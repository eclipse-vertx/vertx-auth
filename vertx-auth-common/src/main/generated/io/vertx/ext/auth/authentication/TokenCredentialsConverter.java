package io.vertx.ext.auth.authentication;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.authentication.TokenCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.authentication.TokenCredentials} original class using Vert.x codegen.
 */
public class TokenCredentialsConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, TokenCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "token":
          if (member.getValue() instanceof String) {
            obj.setToken((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(TokenCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(TokenCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getToken() != null) {
      json.put("token", obj.getToken());
    }
  }
}
