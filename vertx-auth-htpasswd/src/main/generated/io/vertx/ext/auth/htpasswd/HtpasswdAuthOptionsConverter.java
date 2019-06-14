package io.vertx.ext.auth.htpasswd;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonCodec;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions} original class using Vert.x codegen.
 */
public class HtpasswdAuthOptionsConverter implements JsonCodec<HtpasswdAuthOptions, JsonObject> {

  public static final HtpasswdAuthOptionsConverter INSTANCE = new HtpasswdAuthOptionsConverter();

  @Override public JsonObject encode(HtpasswdAuthOptions value) { return (value != null) ? value.toJson() : null; }

  @Override public HtpasswdAuthOptions decode(JsonObject value) { return (value != null) ? new HtpasswdAuthOptions(value) : null; }

  @Override public Class<HtpasswdAuthOptions> getTargetClass() { return HtpasswdAuthOptions.class; }

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, HtpasswdAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "htpasswdFile":
          if (member.getValue() instanceof String) {
            obj.setHtpasswdFile((String)member.getValue());
          }
          break;
        case "plainTextEnabled":
          if (member.getValue() instanceof Boolean) {
            obj.setPlainTextEnabled((Boolean)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(HtpasswdAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(HtpasswdAuthOptions obj, java.util.Map<String, Object> json) {
    if (obj.getHtpasswdFile() != null) {
      json.put("htpasswdFile", obj.getHtpasswdFile());
    }
    json.put("plainTextEnabled", obj.isPlainTextEnabled());
  }
}
