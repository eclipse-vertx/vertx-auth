package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.PubSecKeyOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.PubSecKeyOptions} original class using Vert.x codegen.
 */
public class PubSecKeyOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, PubSecKeyOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "algorithm":
          if (member.getValue() instanceof String) {
            obj.setAlgorithm((String)member.getValue());
          }
          break;
        case "buffer":
          if (member.getValue() instanceof String) {
            obj.setBuffer(io.vertx.core.buffer.Buffer.buffer(BASE64_DECODER.decode((String)member.getValue())));
          }
          break;
        case "id":
          if (member.getValue() instanceof String) {
            obj.setId((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(PubSecKeyOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(PubSecKeyOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    if (obj.getBuffer() != null) {
      json.put("buffer", BASE64_ENCODER.encodeToString(obj.getBuffer().getBytes()));
    }
    if (obj.getId() != null) {
      json.put("id", obj.getId());
    }
  }
}
