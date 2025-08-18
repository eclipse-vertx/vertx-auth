package io.vertx.ext.auth.authentication;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.authentication.TokenCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.authentication.TokenCredentials} original class using Vert.x codegen.
 */
public class TokenCredentialsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, TokenCredentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "token":
          if (member.getValue() instanceof String) {
            obj.setToken((String)member.getValue());
          }
          break;
        case "scopes":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setScopes(list);
          }
          break;
      }
    }
  }

   static void toJson(TokenCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(TokenCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getToken() != null) {
      json.put("token", obj.getToken());
    }
    if (obj.getScopes() != null) {
      JsonArray array = new JsonArray();
      obj.getScopes().forEach(item -> array.add(item));
      json.put("scopes", array);
    }
  }
}
