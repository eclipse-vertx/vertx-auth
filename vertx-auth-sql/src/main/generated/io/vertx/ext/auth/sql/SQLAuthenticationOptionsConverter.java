package io.vertx.ext.auth.sql;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.sql.SQLAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.sql.SQLAuthenticationOptions} original class using Vert.x codegen.
 */
public class SQLAuthenticationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, SQLAuthenticationOptions obj) {
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

  public static void toJson(SQLAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(SQLAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
  }
}
