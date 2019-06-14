package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonCodec;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.KeyStoreOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.KeyStoreOptions} original class using Vert.x codegen.
 */
public class KeyStoreOptionsConverter implements JsonCodec<KeyStoreOptions, JsonObject> {

  public static final KeyStoreOptionsConverter INSTANCE = new KeyStoreOptionsConverter();

  @Override
  public JsonObject encode(KeyStoreOptions value) {
    if (value == null) return null;
    JsonObject json = new JsonObject();
    toJson(value, json);
    return json;
  }

  @Override public KeyStoreOptions decode(JsonObject value) { return (value != null) ? new KeyStoreOptions(value) : null; }

  @Override public Class<KeyStoreOptions> getTargetClass() { return KeyStoreOptions.class; }

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, KeyStoreOptions obj) {
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

  public static void toJson(KeyStoreOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(KeyStoreOptions obj, java.util.Map<String, Object> json) {
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
