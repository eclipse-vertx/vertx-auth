package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.jwt.JWTAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTAuthOptions} original class using Vert.x codegen.
 */
public class JWTAuthOptionsConverter {

  private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();
  private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, JWTAuthOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "keyStore":
          if (member.getValue() instanceof JsonObject) {
            obj.setKeyStore(new io.vertx.ext.auth.jose.KeyStoreOptions((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "pubSecKeys":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.jose.PubSecKeyOptions> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(new io.vertx.ext.auth.jose.PubSecKeyOptions((io.vertx.core.json.JsonObject)item));
            });
            obj.setPubSecKeys(list);
          }
          break;
        case "jwtOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setJWTOptions(new io.vertx.ext.auth.jose.JWTOptions((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
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
      }
    }
  }

   static void toJson(JWTAuthOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(JWTAuthOptions obj, java.util.Map<String, Object> json) {
    if (obj.getPubSecKeys() != null) {
      JsonArray array = new JsonArray();
      obj.getPubSecKeys().forEach(item -> array.add(item.toJson()));
      json.put("pubSecKeys", array);
    }
    if (obj.getJWTOptions() != null) {
      json.put("jwtOptions", obj.getJWTOptions().toJson());
    }
    if (obj.getJwks() != null) {
      JsonArray array = new JsonArray();
      obj.getJwks().forEach(item -> array.add(item));
      json.put("jwks", array);
    }
  }
}
