package io.vertx.ext.auth.authentication;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.authentication.UsernamePasswordCredentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.authentication.UsernamePasswordCredentials} original class using Vert.x codegen.
 */
public class UsernamePasswordCredentialsConverter {


   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, UsernamePasswordCredentials obj) {
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

   static void toJson(UsernamePasswordCredentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(UsernamePasswordCredentials obj, java.util.Map<String, Object> json) {
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
  }
}
