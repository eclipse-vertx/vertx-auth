package io.vertx.ext.auth.htdigest;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.htdigest.HtdigestCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.htdigest.HtdigestCredentials} original class using Vert.x codegen.
 */
public class HtdigestCredentialsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, HtdigestCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "algorithm":
          if (member.getValue() instanceof String) {
            obj.setAlgorithm((String)member.getValue());
          }
          break;
        case "cnonce":
          if (member.getValue() instanceof String) {
            obj.setCnonce((String)member.getValue());
          }
          break;
        case "method":
          if (member.getValue() instanceof String) {
            obj.setMethod((String)member.getValue());
          }
          break;
        case "nc":
          if (member.getValue() instanceof String) {
            obj.setNc((String)member.getValue());
          }
          break;
        case "nonce":
          if (member.getValue() instanceof String) {
            obj.setNonce((String)member.getValue());
          }
          break;
        case "opaque":
          if (member.getValue() instanceof String) {
            obj.setOpaque((String)member.getValue());
          }
          break;
        case "qop":
          if (member.getValue() instanceof String) {
            obj.setQop((String)member.getValue());
          }
          break;
        case "realm":
          if (member.getValue() instanceof String) {
            obj.setRealm((String)member.getValue());
          }
          break;
        case "response":
          if (member.getValue() instanceof String) {
            obj.setResponse((String)member.getValue());
          }
          break;
        case "uri":
          if (member.getValue() instanceof String) {
            obj.setUri((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(HtdigestCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(HtdigestCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getAlgorithm() != null) {
      json.put("algorithm", obj.getAlgorithm());
    }
    if (obj.getCnonce() != null) {
      json.put("cnonce", obj.getCnonce());
    }
    if (obj.getMethod() != null) {
      json.put("method", obj.getMethod());
    }
    if (obj.getNc() != null) {
      json.put("nc", obj.getNc());
    }
    if (obj.getNonce() != null) {
      json.put("nonce", obj.getNonce());
    }
    if (obj.getOpaque() != null) {
      json.put("opaque", obj.getOpaque());
    }
    if (obj.getQop() != null) {
      json.put("qop", obj.getQop());
    }
    if (obj.getRealm() != null) {
      json.put("realm", obj.getRealm());
    }
    if (obj.getResponse() != null) {
      json.put("response", obj.getResponse());
    }
    if (obj.getUri() != null) {
      json.put("uri", obj.getUri());
    }
  }
}
