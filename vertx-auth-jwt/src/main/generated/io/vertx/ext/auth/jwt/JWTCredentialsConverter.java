package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jwt.JWTCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTCredentials} original class using Vert.x codegen.
 */
public class JWTCredentialsConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JWTCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "jwt":
          if (member.getValue() instanceof String) {
            obj.setJwt((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(JWTCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(JWTCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getJwt() != null) {
      json.put("jwt", obj.getJwt());
    }
  }
}
