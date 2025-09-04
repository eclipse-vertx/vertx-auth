package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.DCRRequest}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.DCRRequest} original class using Vert.x codegen.
 */
public class DCRRequestConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, DCRRequest obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "clientId":
          if (member.getValue() instanceof String) {
            obj.setClientId((String)member.getValue());
          }
          break;
        case "registrationAccessToken":
          if (member.getValue() instanceof String) {
            obj.setRegistrationAccessToken((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(DCRRequest obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(DCRRequest obj, java.util.Map<String, Object> json) {
    if (obj.getClientId() != null) {
      json.put("clientId", obj.getClientId());
    }
    if (obj.getRegistrationAccessToken() != null) {
      json.put("registrationAccessToken", obj.getRegistrationAccessToken());
    }
  }
}
