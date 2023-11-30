package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.Oauth2Credentials}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.Oauth2Credentials} original class using Vert.x codegen.
 */
public class Oauth2CredentialsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, Oauth2Credentials obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "code":
          if (member.getValue() instanceof String) {
            obj.setCode((String)member.getValue());
          }
          break;
        case "redirectUri":
          if (member.getValue() instanceof String) {
            obj.setRedirectUri((String)member.getValue());
          }
          break;
        case "codeVerifier":
          if (member.getValue() instanceof String) {
            obj.setCodeVerifier((String)member.getValue());
          }
          break;
        case "scopes":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setScopes(list);
          }
          break;
        case "jwt":
          if (member.getValue() instanceof JsonObject) {
            obj.setJwt(((JsonObject)member.getValue()).copy());
          }
          break;
        case "assertion":
          if (member.getValue() instanceof String) {
            obj.setAssertion((String)member.getValue());
          }
          break;
        case "password":
          if (member.getValue() instanceof String) {
            obj.setPassword((String)member.getValue());
          }
          break;
        case "username":
          if (member.getValue() instanceof String) {
            obj.setUsername((String)member.getValue());
          }
          break;
        case "flow":
          if (member.getValue() instanceof String) {
            obj.setFlow(io.vertx.ext.auth.oauth2.OAuth2FlowType.valueOf((String)member.getValue()));
          }
          break;
      }
    }
  }

   static void toJson(Oauth2Credentials obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(Oauth2Credentials obj, java.util.Map<String, Object> json) {
    if (obj.getCode() != null) {
      json.put("code", obj.getCode());
    }
    if (obj.getRedirectUri() != null) {
      json.put("redirectUri", obj.getRedirectUri());
    }
    if (obj.getCodeVerifier() != null) {
      json.put("codeVerifier", obj.getCodeVerifier());
    }
    if (obj.getScopes() != null) {
      JsonArray array = new JsonArray();
      obj.getScopes().forEach(item -> array.add(item));
      json.put("scopes", array);
    }
    if (obj.getJwt() != null) {
      json.put("jwt", obj.getJwt());
    }
    if (obj.getAssertion() != null) {
      json.put("assertion", obj.getAssertion());
    }
    if (obj.getPassword() != null) {
      json.put("password", obj.getPassword());
    }
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
    if (obj.getFlow() != null) {
      json.put("flow", obj.getFlow().name());
    }
  }
}
