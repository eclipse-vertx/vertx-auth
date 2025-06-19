package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.OAuth2AuthorizationURL}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.OAuth2AuthorizationURL} original class using Vert.x codegen.
 */
public class OAuth2AuthorizationURLConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, OAuth2AuthorizationURL obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "additionalParameters":
          if (member.getValue() instanceof JsonObject) {
            java.util.Map<String, java.lang.String> map = new java.util.LinkedHashMap<>();
            ((Iterable<java.util.Map.Entry<String, Object>>)member.getValue()).forEach(entry -> {
              if (entry.getValue() instanceof String)
                map.put(entry.getKey(), (String)entry.getValue());
            });
            obj.setAdditionalParameters(map);
          }
          break;
        case "redirectUri":
          if (member.getValue() instanceof String) {
            obj.setRedirectUri((String)member.getValue());
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
        case "state":
          if (member.getValue() instanceof String) {
            obj.setState((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(OAuth2AuthorizationURL obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(OAuth2AuthorizationURL obj, java.util.Map<String, Object> json) {
    if (obj.getAdditionalParameters() != null) {
      JsonObject map = new JsonObject();
      obj.getAdditionalParameters().forEach((key, value) -> map.put(key, value));
      json.put("additionalParameters", map);
    }
    if (obj.getRedirectUri() != null) {
      json.put("redirectUri", obj.getRedirectUri());
    }
    if (obj.getScopes() != null) {
      JsonArray array = new JsonArray();
      obj.getScopes().forEach(item -> array.add(item));
      json.put("scopes", array);
    }
    if (obj.getState() != null) {
      json.put("state", obj.getState());
    }
  }
}
