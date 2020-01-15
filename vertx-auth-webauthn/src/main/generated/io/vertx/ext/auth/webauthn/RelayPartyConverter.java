package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.RelayParty}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.RelayParty} original class using Vert.x codegen.
 */
public class RelayPartyConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, RelayParty obj) {
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

  public static void toJson(RelayParty obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(RelayParty obj, java.util.Map<String, Object> json) {
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
