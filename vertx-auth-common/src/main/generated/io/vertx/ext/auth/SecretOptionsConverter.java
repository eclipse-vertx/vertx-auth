package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter for {@link io.vertx.ext.auth.SecretOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.SecretOptions} original class using Vert.x codegen.
 */
public class SecretOptionsConverter {

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, SecretOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "secret":
          if (member.getValue() instanceof String) {
            obj.setSecret((String)member.getValue());
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

  public static void toJson(SecretOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(SecretOptions obj, java.util.Map<String, Object> json) {
    if (obj.getSecret() != null) {
      json.put("secret", obj.getSecret());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
  }
}
