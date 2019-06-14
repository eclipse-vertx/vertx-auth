package io.vertx.ext.auth.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import io.vertx.core.spi.json.JsonCodec;

/**
 * Converter and Codec for {@link io.vertx.ext.auth.jwt.JWTAuthOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTAuthOptions} original class using Vert.x codegen.
 */
public class JWTAuthOptionsConverter implements JsonCodec<JWTAuthOptions, JsonObject> {

  public static final JWTAuthOptionsConverter INSTANCE = new JWTAuthOptionsConverter();

  @Override
  public JsonObject encode(JWTAuthOptions value) {
    if (value == null) return null;
    JsonObject json = new JsonObject();
    toJson(value, json);
    return json;
  }

  @Override public JWTAuthOptions decode(JsonObject value) { return (value != null) ? new JWTAuthOptions(value) : null; }

  @Override public Class<JWTAuthOptions> getTargetClass() { return JWTAuthOptions.class; }

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
            obj.setJWTOptions(io.vertx.ext.jwt.JWTOptionsConverter.INSTANCE.decode((JsonObject)member.getValue()));
          }
          break;
        case "keyStore":
          if (member.getValue() instanceof JsonObject) {
            obj.setKeyStore(io.vertx.ext.auth.KeyStoreOptionsConverter.INSTANCE.decode((JsonObject)member.getValue()));
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
                list.add(io.vertx.ext.auth.PubSecKeyOptionsConverter.INSTANCE.decode((JsonObject)item));
            });
            obj.setPubSecKeys(list);
          }
          break;
        case "secrets":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.SecretOptions> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(io.vertx.ext.auth.SecretOptionsConverter.INSTANCE.decode((JsonObject)item));
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
    if (obj.getJWTOptions() != null) {
      json.put("jwtOptions", io.vertx.ext.jwt.JWTOptionsConverter.INSTANCE.encode(obj.getJWTOptions()));
    }
    if (obj.getKeyStore() != null) {
      json.put("keyStore", io.vertx.ext.auth.KeyStoreOptionsConverter.INSTANCE.encode(obj.getKeyStore()));
    }
    if (obj.getPermissionsClaimKey() != null) {
      json.put("permissionsClaimKey", obj.getPermissionsClaimKey());
    }
    if (obj.getPubSecKeys() != null) {
      JsonArray array = new JsonArray();
      obj.getPubSecKeys().forEach(item -> array.add(io.vertx.ext.auth.PubSecKeyOptionsConverter.INSTANCE.encode(item)));
      json.put("pubSecKeys", array);
    }
    if (obj.getSecrets() != null) {
      JsonArray array = new JsonArray();
      obj.getSecrets().forEach(item -> array.add(io.vertx.ext.auth.SecretOptionsConverter.INSTANCE.encode(item)));
      json.put("secrets", array);
    }
  }
}
