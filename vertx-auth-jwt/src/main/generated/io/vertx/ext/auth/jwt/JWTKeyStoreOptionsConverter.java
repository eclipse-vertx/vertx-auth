package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter for {@link io.vertx.ext.auth.jwt.JWTKeyStoreOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTKeyStoreOptions} original class using Vert.x codegen.
 */
public class JWTKeyStoreOptionsConverter {

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JWTKeyStoreOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "password":
          if (member.getValue() instanceof String) {
            obj.setPassword((String)member.getValue());
          }
          break;
        case "path":
          if (member.getValue() instanceof String) {
            obj.setPath((String)member.getValue());
          }
          break;
        case "type":
          if (member.getValue() instanceof String) {
            obj.setType((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(JWTKeyStoreOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(JWTKeyStoreOptions obj, java.util.Map<String, Object> json) {
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getPath() != null) {
      json.put("path", obj.getPath());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
  }
}
