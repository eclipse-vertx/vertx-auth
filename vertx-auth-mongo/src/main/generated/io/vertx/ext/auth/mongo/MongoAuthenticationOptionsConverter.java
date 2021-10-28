package io.vertx.ext.auth.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.mongo.MongoAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.mongo.MongoAuthenticationOptions} original class using Vert.x codegen.
 */
public class MongoAuthenticationOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, MongoAuthenticationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "collectionName":
          if (member.getValue() instanceof String) {
            obj.setCollectionName((String)member.getValue());
          }
          break;
        case "passwordCredentialField":
          if (member.getValue() instanceof String) {
            obj.setPasswordCredentialField((String)member.getValue());
          }
          break;
        case "passwordField":
          if (member.getValue() instanceof String) {
            obj.setPasswordField((String)member.getValue());
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
    if (obj.getPasswordCredentialField() != null) {
      json.put("passwordCredentialField", obj.getPasswordCredentialField());
    }
    if (obj.getPasswordField() != null) {
      json.put("passwordField", obj.getPasswordField());
    }
    if (obj.getUsernameCredentialField() != null) {
      json.put("usernameCredentialField", obj.getUsernameCredentialField());
    }
    if (obj.getUsernameField() != null) {
      json.put("usernameField", obj.getUsernameField());
    }
  }
}
