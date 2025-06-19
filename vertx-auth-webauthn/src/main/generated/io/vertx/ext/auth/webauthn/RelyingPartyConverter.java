package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.RelyingParty}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.RelyingParty} original class using Vert.x codegen.
 */
public class RelyingPartyConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, RelyingParty obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "icon":
          if (member.getValue() instanceof String) {
            obj.setIcon((String)member.getValue());
          }
          break;
        case "id":
          if (member.getValue() instanceof String) {
            obj.setId((String)member.getValue());
          }
          break;
        case "name":
          if (member.getValue() instanceof String) {
            obj.setName((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(RelyingParty obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(RelyingParty obj, java.util.Map<String, Object> json) {
    if (obj.getIcon() != null) {
      json.put("icon", obj.getIcon());
    }
    if (obj.getId() != null) {
      json.put("id", obj.getId());
    }
    if (obj.getName() != null) {
      json.put("name", obj.getName());
    }
  }
}
