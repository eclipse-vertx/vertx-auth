package io.vertx.ext.auth.jdbc;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jdbc.JDBCAuthorizationOptions} original class using Vert.x codegen.
 */
public class JDBCAuthorizationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JDBCAuthorizationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "permissionsQuery":
          if (member.getValue() instanceof String) {
            obj.setPermissionsQuery((String)member.getValue());
          }
          break;
        case "rolesQuery":
          if (member.getValue() instanceof String) {
            obj.setRolesQuery((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(JDBCAuthorizationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(JDBCAuthorizationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getPermissionsQuery() != null) {
      json.put("permissionsQuery", obj.getPermissionsQuery());
    }
    if (obj.getRolesQuery() != null) {
      json.put("rolesQuery", obj.getRolesQuery());
    }
  }
}
