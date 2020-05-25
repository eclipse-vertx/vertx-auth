package io.vertx.ext.auth.jdbc;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jdbc.JDBCAuthInfo}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuthInfo} original class using Vert.x codegen.
 */
public class JDBCAuthInfoConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JDBCAuthInfo obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "password":
          if (member.getValue() instanceof String) {
            obj.setPassword((String)member.getValue());
          }
          break;
        case "username":
          if (member.getValue() instanceof String) {
            obj.setUsername((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(JDBCAuthInfo obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(JDBCAuthInfo obj, java.util.Map<String, Object> json) {
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
  }
}
