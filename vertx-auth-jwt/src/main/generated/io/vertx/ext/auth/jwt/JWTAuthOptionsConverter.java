package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter for {@link io.vertx.ext.auth.jwt.JWTAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTAuthOptions} original class using Vert.x codegen.
 */
public class JWTAuthOptionsConverter {

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JWTAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "jwks":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.core.json.JsonObject> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(((JsonObject)item).copy());
            });
            obj.setJwks(list);
          }
          break;
        case "jwtOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setJWTOptions(new io.vertx.ext.jwt.JWTOptions((JsonObject)member.getValue()));
          }
          break;
        case "keyStore":
          if (member.getValue() instanceof JsonObject) {
            obj.setKeyStore(new io.vertx.ext.auth.KeyStoreOptions((JsonObject)member.getValue()));
          }
          break;
        case "permissionsClaimKey":
          if (member.getValue() instanceof String) {
            obj.setPermissionsClaimKey((String)member.getValue());
          }
          break;
        case "pubSecKeys":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.PubSecKeyOptions> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(new io.vertx.ext.auth.PubSecKeyOptions((JsonObject)item));
            });
            obj.setPubSecKeys(list);
          }
          break;
        case "secrets":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.SecretOptions> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(new io.vertx.ext.auth.SecretOptions((JsonObject)item));
            });
            obj.setSecrets(list);
          }
          break;
      }
    }
  }

  public static void toJson(JWTAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(JWTAuthOptions obj, java.util.Map<String, Object> json) {
    if (obj.getJwks() != null) {
      JsonArray array = new JsonArray();
      obj.getJwks().forEach(item -> array.add(item));
      json.put("jwks", array);
    }
    if (obj.getPermissionsClaimKey() != null) {
      json.put("permissionsClaimKey", obj.getPermissionsClaimKey());
    }
  }
}
