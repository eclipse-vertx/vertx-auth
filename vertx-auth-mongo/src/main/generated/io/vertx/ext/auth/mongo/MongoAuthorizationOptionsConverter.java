package io.vertx.ext.auth.mongo;

import io.vertx.core.json.JsonObject;

/**
 * Converter and mapper for {@link MongoAuthorizationOptions}.
 * NOTE: This class has been automatically generated from the {@link MongoAuthorizationOptions} original class using Vert.x codegen.
 */
public class MongoAuthorizationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, MongoAuthorizationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "collectionName":
          if (member.getValue() instanceof String) {
            obj.setCollectionName((String)member.getValue());
          }
          break;
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
        case "shared":
          if (member.getValue() instanceof Boolean) {
            obj.setShared((Boolean)member.getValue());
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
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getDatasourceName() != null) {
      json.put("datasourceName", obj.getDatasourceName());
    }
    if (obj.getPermissionField() != null) {
      json.put("permissionField", obj.getPermissionField());
    }
    if (obj.getRoleField() != null) {
      json.put("roleField", obj.getRoleField());
    }
    json.put("shared", obj.getShared());
    if (obj.getUsernameField() != null) {
      json.put("usernameField", obj.getUsernameField());
    }
  }
}
