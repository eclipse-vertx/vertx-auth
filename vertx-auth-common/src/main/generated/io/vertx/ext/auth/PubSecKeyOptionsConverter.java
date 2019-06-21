package io.vertx.ext.auth;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonDecoder;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.PubSecKeyOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.PubSecKeyOptions} original class using Vert.x codegen.
 */
public class PubSecKeyOptionsConverter implements JsonDecoder<PubSecKeyOptions, JsonObject> {

  public static final PubSecKeyOptionsConverter INSTANCE = new PubSecKeyOptionsConverter();

  @Override public PubSecKeyOptions decode(JsonObject value) { return (value != null) ? new PubSecKeyOptions(value) : null; }

  @Override public Class<PubSecKeyOptions> getTargetClass() { return PubSecKeyOptions.class; }

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, PubSecKeyOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "algorithm":
          if (member.getValue() instanceof String) {
            obj.setAlgorithm((String)member.getValue());
          }
          break;
        case "certificate":
          if (member.getValue() instanceof Boolean) {
            obj.setCertificate((Boolean)member.getValue());
          }
          break;
        case "publicKey":
          if (member.getValue() instanceof String) {
            obj.setPublicKey((String)member.getValue());
          }
          break;
        case "secretKey":
          if (member.getValue() instanceof String) {
            obj.setSecretKey((String)member.getValue());
          }
          break;
        case "symmetric":
          if (member.getValue() instanceof Boolean) {
            obj.setSymmetric((Boolean)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(PubSecKeyOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(PubSecKeyOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    json.put("certificate", obj.isCertificate());
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    if (obj.getSecretKey() != null) {
      json.put("secretKey", obj.getSecretKey());
    }
    json.put("symmetric", obj.isSymmetric());
  }
}
