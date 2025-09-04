package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.DCRResponse}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.DCRResponse} original class using Vert.x codegen.
 */
public class DCRResponseConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, DCRResponse obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "id":
          break;
        case "clientId":
          break;
        case "enabled":
          break;
        case "clientAuthenticationType":
          break;
        case "secret":
          break;
        case "registrationAccessToken":
          break;
      }
    }
  }

   static void toJson(DCRResponse obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(DCRResponse obj, java.util.Map<String, Object> json) {
    if (obj.getId() != null) {
      json.put("id", obj.getId());
    }
    if (obj.getClientId() != null) {
      json.put("clientId", obj.getClientId());
    }
    json.put("enabled", obj.isEnabled());
    if (obj.getClientAuthenticationType() != null) {
      json.put("clientAuthenticationType", obj.getClientAuthenticationType());
    }
    if (obj.getSecret() != null) {
      json.put("secret", obj.getSecret());
    }
    if (obj.getRegistrationAccessToken() != null) {
      json.put("registrationAccessToken", obj.getRegistrationAccessToken());
    }
  }
}
