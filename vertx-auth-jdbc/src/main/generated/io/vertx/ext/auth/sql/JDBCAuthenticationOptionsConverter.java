package io.vertx.ext.auth.sql;

import io.vertx.core.json.JsonObject;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.sql.JDBCAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.sql.JDBCAuthenticationOptions} original class using Vert.x codegen.
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
  }
}
