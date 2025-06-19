package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.AttestationCertificates}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.AttestationCertificates} original class using Vert.x codegen.
 */
public class AttestationCertificatesConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, AttestationCertificates obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "alg":
          if (member.getValue() instanceof String) {
            obj.setAlg(io.vertx.ext.auth.webauthn.PublicKeyCredential.valueOf((String)member.getValue()));
          }
          break;
        case "x5c":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setX5c(list);
          }
          break;
      }
    }
  }

   static void toJson(AttestationCertificates obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(AttestationCertificates obj, java.util.Map<String, Object> json) {
    if (obj.getAlg() != null) {
      json.put("alg", obj.getAlg().name());
    }
    if (obj.getX5c() != null) {
      JsonArray array = new JsonArray();
      obj.getX5c().forEach(item -> array.add(item));
      json.put("x5c", array);
    }
  }
}
