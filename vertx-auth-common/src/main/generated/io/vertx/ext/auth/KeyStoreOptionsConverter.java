package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.KeyStoreOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.KeyStoreOptions} original class using Vert.x codegen.
 */
public class KeyStoreOptionsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, KeyStoreOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "type":
          if (member.getValue() instanceof String) {
            obj.setType((String)member.getValue());
          }
          break;
        case "provider":
          if (member.getValue() instanceof String) {
            obj.setProvider((String)member.getValue());
          }
          break;
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
        case "passwordProtection":
          if (member.getValue() instanceof JsonObject) {
            java.util.Map<String, java.lang.String> map = new java.util.LinkedHashMap<>();
            ((Iterable<java.util.Map.Entry<String, Object>>)member.getValue()).forEach(entry -> {
              if (entry.getValue() instanceof String)
                map.put(entry.getKey(), (String)entry.getValue());
            });
            obj.setPasswordProtection(map);
          }
          break;
      }
    }
  }

   static void toJson(KeyStoreOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(KeyStoreOptions obj, java.util.Map<String, Object> json) {
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
    if (obj.getProvider() != null) {
      json.put("provider", obj.getProvider());
    }
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getPath() != null) {
      json.put("path", obj.getPath());
    }
    if (obj.getPasswordProtection() != null) {
      JsonObject map = new JsonObject();
      obj.getPasswordProtection().forEach((key, value) -> map.put(key, value));
      json.put("passwordProtection", map);
    }
  }
}
