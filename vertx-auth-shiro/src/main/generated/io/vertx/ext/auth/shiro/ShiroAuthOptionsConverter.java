package io.vertx.ext.auth.shiro;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.shiro.ShiroAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.shiro.ShiroAuthOptions} original class using Vert.x codegen.
 */
public class ShiroAuthOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, ShiroAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "config":
          if (member.getValue() instanceof JsonObject) {
            obj.setConfig(((JsonObject)member.getValue()).copy());
          }
          break;
        case "type":
          if (member.getValue() instanceof String) {
            obj.setType(io.vertx.ext.auth.shiro.ShiroAuthRealmType.valueOf((String)member.getValue()));
          }
          break;
      }
    }
  }

  public static void toJson(ShiroAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(ShiroAuthOptions obj, java.util.Map<String, Object> json) {
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType().name());
    }
  }
}
