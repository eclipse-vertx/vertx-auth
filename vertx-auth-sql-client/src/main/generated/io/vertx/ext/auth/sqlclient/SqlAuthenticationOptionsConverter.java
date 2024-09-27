package io.vertx.ext.auth.sqlclient;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.sqlclient.SqlAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.sqlclient.SqlAuthenticationOptions} original class using Vert.x codegen.
 */
public class SqlAuthenticationOptionsConverter {

  private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();
  private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, SqlAuthenticationOptions obj) {
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

   static void toJson(SqlAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(SqlAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
  }
}
