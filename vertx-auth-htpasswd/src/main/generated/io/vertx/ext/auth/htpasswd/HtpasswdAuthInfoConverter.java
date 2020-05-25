package io.vertx.ext.auth.htpasswd;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.htpasswd.HtpasswdAuthInfo}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.htpasswd.HtpasswdAuthInfo} original class using Vert.x codegen.
 */
public class HtpasswdAuthInfoConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, HtpasswdAuthInfo obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "password":
          if (member.getValue() instanceof String) {
            obj.setPassword((String)member.getValue());
          }
          break;
        case "username":
          if (member.getValue() instanceof String) {
            obj.setUsername((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(HtpasswdAuthInfo obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(HtpasswdAuthInfo obj, java.util.Map<String, Object> json) {
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
  }
}
