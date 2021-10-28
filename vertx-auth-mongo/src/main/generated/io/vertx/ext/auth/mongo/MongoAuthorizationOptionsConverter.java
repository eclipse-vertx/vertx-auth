package io.vertx.ext.auth.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.mongo.MongoAuthorizationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.mongo.MongoAuthorizationOptions} original class using Vert.x codegen.
 */
public class MongoAuthorizationOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, MongoAuthorizationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "collectionName":
          if (member.getValue() instanceof String) {
            obj.setCollectionName((String)member.getValue());
          }
          break;
        case "permissionField":
          if (member.getValue() instanceof String) {
            obj.setPermissionField((String)member.getValue());
          }
          break;
        case "roleField":
          if (member.getValue() instanceof String) {
            obj.setRoleField((String)member.getValue());
          }
          break;
        case "usernameField":
          if (member.getValue() instanceof String) {
            obj.setUsernameField((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(MongoAuthorizationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(MongoAuthorizationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getCollectionName() != null) {
      json.put("collectionName", obj.getCollectionName());
    }
    if (obj.getPermissionField() != null) {
      json.put("permissionField", obj.getPermissionField());
    }
    if (obj.getRoleField() != null) {
      json.put("roleField", obj.getRoleField());
    }
    if (obj.getUsernameField() != null) {
      json.put("usernameField", obj.getUsernameField());
    }
  }
}
