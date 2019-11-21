package io.vertx.ext.auth.jdbc;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuthenticationOptions} original class using Vert.x codegen.
 */
public class JDBCAuthenticationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JDBCAuthenticationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authenticationQuery":
          if (member.getValue() instanceof String) {
            obj.setAuthenticationQuery((String)member.getValue());
          }
          break;
<<<<<<< HEAD
<<<<<<< HEAD
=======
        case "config":
          if (member.getValue() instanceof JsonObject) {
            obj.setConfig(((JsonObject)member.getValue()).copy());
          }
          break;
        case "datasourceName":
          if (member.getValue() instanceof String) {
            obj.setDatasourceName((String)member.getValue());
          }
          break;
        case "shared":
          if (member.getValue() instanceof Boolean) {
            obj.setShared((Boolean)member.getValue());
          }
          break;
>>>>>>> updated code based on comments from Paulo:
=======
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
      }
    }
  }

  public static void toJson(JDBCAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(JDBCAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
<<<<<<< HEAD
<<<<<<< HEAD
=======
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getDatasourceName() != null) {
      json.put("datasourceName", obj.getDatasourceName());
    }
    json.put("shared", obj.isShared());
>>>>>>> updated code based on comments from Paulo:
=======
>>>>>>> Added back the class JDBCAuth to be backward compatible. Note that the whole class is marked as deprecated to encourage people to switch to JDBCAuthencation / JDBCAuthorization
  }
}
