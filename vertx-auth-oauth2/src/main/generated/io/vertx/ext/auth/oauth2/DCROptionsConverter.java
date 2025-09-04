package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.DCROptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.DCROptions} original class using Vert.x codegen.
 */
public class DCROptionsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, DCROptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "httpClientOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setHttpClientOptions(new io.vertx.core.http.HttpClientOptions((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "resourceUri":
          break;
        case "initialAccessToken":
          if (member.getValue() instanceof String) {
            obj.setInitialAccessToken((String)member.getValue());
          }
          break;
        case "site":
          if (member.getValue() instanceof String) {
            obj.setSite((String)member.getValue());
          }
          break;
        case "tenant":
          if (member.getValue() instanceof String) {
            obj.setTenant((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(DCROptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(DCROptions obj, java.util.Map<String, Object> json) {
    if (obj.getHttpClientOptions() != null) {
      json.put("httpClientOptions", obj.getHttpClientOptions().toJson());
    }
    if (obj.resourceUri() != null) {
      json.put("resourceUri", obj.resourceUri());
    }
    if (obj.getInitialAccessToken() != null) {
      json.put("initialAccessToken", obj.getInitialAccessToken());
    }
    if (obj.getSite() != null) {
      json.put("site", obj.getSite());
    }
    if (obj.getTenant() != null) {
      json.put("tenant", obj.getTenant());
    }
  }
}
