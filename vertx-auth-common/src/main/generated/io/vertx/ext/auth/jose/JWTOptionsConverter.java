package io.vertx.ext.auth.jose;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jose.JWTOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jose.JWTOptions} original class using Vert.x codegen.
 */
public class JWTOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JWTOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "algorithm":
          if (member.getValue() instanceof String) {
            obj.setAlgorithm((String)member.getValue());
          }
          break;
        case "audience":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setAudience(list);
          }
          break;
        case "audiences":
          if (member.getValue() instanceof JsonArray) {
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                obj.addAudience((String)item);
            });
          }
          break;
        case "expiresInMinutes":
          if (member.getValue() instanceof Number) {
            obj.setExpiresInMinutes(((Number)member.getValue()).intValue());
          }
          break;
        case "expiresInSeconds":
          if (member.getValue() instanceof Number) {
            obj.setExpiresInSeconds(((Number)member.getValue()).intValue());
          }
          break;
        case "header":
          if (member.getValue() instanceof JsonObject) {
            obj.setHeader(((JsonObject)member.getValue()).copy());
          }
          break;
        case "ignoreExpiration":
          if (member.getValue() instanceof Boolean) {
            obj.setIgnoreExpiration((Boolean)member.getValue());
          }
          break;
        case "issuer":
          if (member.getValue() instanceof String) {
            obj.setIssuer((String)member.getValue());
          }
          break;
        case "leeway":
          if (member.getValue() instanceof Number) {
            obj.setLeeway(((Number)member.getValue()).intValue());
          }
          break;
        case "noTimestamp":
          if (member.getValue() instanceof Boolean) {
            obj.setNoTimestamp((Boolean)member.getValue());
          }
          break;
        case "nonceAlgorithm":
          if (member.getValue() instanceof String) {
            obj.setNonceAlgorithm((String)member.getValue());
          }
          break;
        case "permissions":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setPermissions(list);
          }
          break;
        case "subject":
          if (member.getValue() instanceof String) {
            obj.setSubject((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(JWTOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(JWTOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    if (obj.getAudience() != null) {
      JsonArray array = new JsonArray();
      obj.getAudience().forEach(item -> array.add(item));
      json.put("audience", array);
    }
    json.put("expiresInSeconds", obj.getExpiresInSeconds());
    if (obj.getHeader() != null) {
      json.put("header", obj.getHeader());
    }
    json.put("ignoreExpiration", obj.isIgnoreExpiration());
    if (obj.getIssuer() != null) {
      json.put("issuer", obj.getIssuer());
    }
    json.put("leeway", obj.getLeeway());
    json.put("noTimestamp", obj.isNoTimestamp());
    if (obj.getNonceAlgorithm() != null) {
      json.put("nonceAlgorithm", obj.getNonceAlgorithm());
    }
    if (obj.getPermissions() != null) {
      JsonArray array = new JsonArray();
      obj.getPermissions().forEach(item -> array.add(item));
      json.put("permissions", array);
    }
    if (obj.getSubject() != null) {
      json.put("subject", obj.getSubject());
    }
  }
}
