package io.vertx.ext.auth.sql;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.sql.SqlAuthorizationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.sql.SqlAuthorizationOptions} original class using Vert.x codegen.
 */
public class SqlAuthorizationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, SqlAuthorizationOptions obj) {
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

  public static void toJson(SqlAuthorizationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(SqlAuthorizationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getPermissionsQuery() != null) {
      json.put("permissionsQuery", obj.getPermissionsQuery());
    }
    if (obj.getRolesQuery() != null) {
      json.put("rolesQuery", obj.getRolesQuery());
    }
  }
}
