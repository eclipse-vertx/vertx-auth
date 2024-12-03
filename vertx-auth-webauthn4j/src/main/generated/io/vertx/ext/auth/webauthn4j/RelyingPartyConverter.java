package io.vertx.ext.auth.webauthn4j;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn4j.RelyingParty}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn4j.RelyingParty} original class using Vert.x codegen.
 */
public class RelyingPartyConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, RelyingParty obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
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
    if (obj.getId() != null) {
      json.put("id", obj.getId());
    }
    if (obj.getName() != null) {
      json.put("name", obj.getName());
    }
  }
}
