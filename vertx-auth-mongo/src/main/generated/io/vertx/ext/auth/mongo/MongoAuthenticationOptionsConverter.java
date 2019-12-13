package io.vertx.ext.auth.mongo;

import io.vertx.core.json.JsonObject;

/**
 * Converter and mapper for {@link MongoAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link MongoAuthenticationOptions} original class using Vert.x codegen.
 */
public class MongoAuthenticationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, MongoAuthenticationOptions obj) {
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
        case "passwordField":
          if (member.getValue() instanceof String) {
            obj.setPasswordField((String)member.getValue());
          }
          break;
        case "saltField":
          if (member.getValue() instanceof String) {
            obj.setSaltField((String)member.getValue());
          }
          break;
        case "saltStyle":
          if (member.getValue() instanceof String) {
            obj.setSaltStyle(HashSaltStyle.valueOf((String)member.getValue()));
          }
          break;
        case "shared":
          if (member.getValue() instanceof Boolean) {
            obj.setShared((Boolean)member.getValue());
          }
          break;
        case "usernameCredentialField":
          if (member.getValue() instanceof String) {
            obj.setUsernameCredentialField((String)member.getValue());
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

  public static void toJson(MongoAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(MongoAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getCollectionName() != null) {
      json.put("collectionName", obj.getCollectionName());
    }
    if (obj.getConfig() != null) {
      json.put("config", obj.getConfig());
    }
    if (obj.getDatasourceName() != null) {
      json.put("datasourceName", obj.getDatasourceName());
    }
    if (obj.getPasswordField() != null) {
      json.put("passwordField", obj.getPasswordField());
    }
    if (obj.getSaltField() != null) {
      json.put("saltField", obj.getSaltField());
    }
    if (obj.getSaltStyle() != null) {
      json.put("saltStyle", obj.getSaltStyle().name());
    }
    json.put("shared", obj.getShared());
    if (obj.getUsernameCredentialField() != null) {
      json.put("usernameCredentialField", obj.getUsernameCredentialField());
    }
    if (obj.getUsernameField() != null) {
      json.put("usernameField", obj.getUsernameField());
    }
  }
}
