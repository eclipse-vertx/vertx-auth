package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonCodec;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.jwt.JWTKeyStoreOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTKeyStoreOptions} original class using Vert.x codegen.
 */
public class JWTKeyStoreOptionsConverter implements JsonCodec<JWTKeyStoreOptions, JsonObject> {

  public static final JWTKeyStoreOptionsConverter INSTANCE = new JWTKeyStoreOptionsConverter();

  @Override
  public JsonObject encode(JWTKeyStoreOptions value) {
    if (value == null) return null;
    JsonObject json = new JsonObject();
    toJson(value, json);
    return json;
  }

  @Override public JWTKeyStoreOptions decode(JsonObject value) { return (value != null) ? new JWTKeyStoreOptions(value) : null; }

  @Override public Class<JWTKeyStoreOptions> getTargetClass() { return JWTKeyStoreOptions.class; }

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
