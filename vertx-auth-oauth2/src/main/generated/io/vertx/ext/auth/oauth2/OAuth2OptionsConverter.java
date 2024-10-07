package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.oauth2.OAuth2Options}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.OAuth2Options} original class using Vert.x codegen.
 */
public class OAuth2OptionsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, OAuth2Options obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "site":
          if (member.getValue() instanceof String) {
            obj.setSite((String)member.getValue());
          }
          break;
        case "authorizationPath":
          if (member.getValue() instanceof String) {
            obj.setAuthorizationPath((String)member.getValue());
          }
          break;
        case "tokenPath":
          if (member.getValue() instanceof String) {
            obj.setTokenPath((String)member.getValue());
          }
          break;
        case "revocationPath":
          if (member.getValue() instanceof String) {
            obj.setRevocationPath((String)member.getValue());
          }
          break;
        case "clientId":
          if (member.getValue() instanceof String) {
            obj.setClientId((String)member.getValue());
          }
          break;
        case "clientSecret":
          if (member.getValue() instanceof String) {
            obj.setClientSecret((String)member.getValue());
          }
          break;
        case "useBasicAuthorization":
          if (member.getValue() instanceof Boolean) {
            obj.setUseBasicAuthorization((Boolean)member.getValue());
          }
          break;
        case "clientAssertionType":
          if (member.getValue() instanceof String) {
            obj.setClientAssertionType((String)member.getValue());
          }
          break;
        case "clientAssertion":
          if (member.getValue() instanceof String) {
            obj.setClientAssertion((String)member.getValue());
          }
          break;
        case "userAgent":
          if (member.getValue() instanceof String) {
            obj.setUserAgent((String)member.getValue());
          }
          break;
        case "headers":
          if (member.getValue() instanceof JsonObject) {
            obj.setHeaders(((JsonObject)member.getValue()).copy());
          }
          break;
        case "pubSecKeys":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.PubSecKeyOptions> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof JsonObject)
                list.add(new io.vertx.ext.auth.PubSecKeyOptions((io.vertx.core.json.JsonObject)item));
            });
            obj.setPubSecKeys(list);
          }
          break;
        case "logoutPath":
          if (member.getValue() instanceof String) {
            obj.setLogoutPath((String)member.getValue());
          }
          break;
        case "userInfoPath":
          if (member.getValue() instanceof String) {
            obj.setUserInfoPath((String)member.getValue());
          }
          break;
        case "scopeSeparator":
          if (member.getValue() instanceof String) {
            obj.setScopeSeparator((String)member.getValue());
          }
          break;
        case "extraParameters":
          if (member.getValue() instanceof JsonObject) {
            obj.setExtraParameters(((JsonObject)member.getValue()).copy());
          }
          break;
        case "introspectionPath":
          if (member.getValue() instanceof String) {
            obj.setIntrospectionPath((String)member.getValue());
          }
          break;
        case "userInfoParameters":
          if (member.getValue() instanceof JsonObject) {
            obj.setUserInfoParameters(((JsonObject)member.getValue()).copy());
          }
          break;
        case "jwkPath":
          if (member.getValue() instanceof String) {
            obj.setJwkPath((String)member.getValue());
          }
          break;
        case "jwtOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setJWTOptions(new io.vertx.ext.auth.JWTOptions((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "validateIssuer":
          if (member.getValue() instanceof Boolean) {
            obj.setValidateIssuer((Boolean)member.getValue());
          }
          break;
        case "tenant":
          if (member.getValue() instanceof String) {
            obj.setTenant((String)member.getValue());
          }
          break;
        case "supportedGrantTypes":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setSupportedGrantTypes(list);
          }
          break;
        case "httpClientOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setHttpClientOptions(new io.vertx.core.http.HttpClientOptions((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "jwkMaxAgeInSeconds":
          if (member.getValue() instanceof Number) {
            obj.setJwkMaxAgeInSeconds(((Number)member.getValue()).longValue());
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

   static void toJson(OAuth2Options obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(OAuth2Options obj, java.util.Map<String, Object> json) {
    if (obj.getSite() != null) {
      json.put("site", obj.getSite());
    }
    if (obj.getAuthorizationPath() != null) {
      json.put("authorizationPath", obj.getAuthorizationPath());
    }
    if (obj.getTokenPath() != null) {
      json.put("tokenPath", obj.getTokenPath());
    }
    if (obj.getRevocationPath() != null) {
      json.put("revocationPath", obj.getRevocationPath());
    }
    if (obj.getClientId() != null) {
      json.put("clientId", obj.getClientId());
    }
    if (obj.getClientSecret() != null) {
      json.put("clientSecret", obj.getClientSecret());
    }
    json.put("useBasicAuthorization", obj.isUseBasicAuthorization());
    if (obj.getClientAssertionType() != null) {
      json.put("clientAssertionType", obj.getClientAssertionType());
    }
    if (obj.getClientAssertion() != null) {
      json.put("clientAssertion", obj.getClientAssertion());
    }
    if (obj.getUserAgent() != null) {
      json.put("userAgent", obj.getUserAgent());
    }
    if (obj.getHeaders() != null) {
      json.put("headers", obj.getHeaders());
    }
    if (obj.getPubSecKeys() != null) {
      JsonArray array = new JsonArray();
      obj.getPubSecKeys().forEach(item -> array.add(item.toJson()));
      json.put("pubSecKeys", array);
    }
    if (obj.getLogoutPath() != null) {
      json.put("logoutPath", obj.getLogoutPath());
    }
    if (obj.getUserInfoPath() != null) {
      json.put("userInfoPath", obj.getUserInfoPath());
    }
    if (obj.getScopeSeparator() != null) {
      json.put("scopeSeparator", obj.getScopeSeparator());
    }
    if (obj.getExtraParameters() != null) {
      json.put("extraParameters", obj.getExtraParameters());
    }
    if (obj.getIntrospectionPath() != null) {
      json.put("introspectionPath", obj.getIntrospectionPath());
    }
    if (obj.getUserInfoParameters() != null) {
      json.put("userInfoParameters", obj.getUserInfoParameters());
    }
    if (obj.getJwkPath() != null) {
      json.put("jwkPath", obj.getJwkPath());
    }
    if (obj.getJWTOptions() != null) {
      json.put("jwtOptions", obj.getJWTOptions().toJson());
    }
    json.put("validateIssuer", obj.isValidateIssuer());
    if (obj.getTenant() != null) {
      json.put("tenant", obj.getTenant());
    }
    if (obj.getSupportedGrantTypes() != null) {
      JsonArray array = new JsonArray();
      obj.getSupportedGrantTypes().forEach(item -> array.add(item));
      json.put("supportedGrantTypes", array);
    }
    if (obj.getHttpClientOptions() != null) {
      json.put("httpClientOptions", obj.getHttpClientOptions().toJson());
    }
    json.put("jwkMaxAgeInSeconds", obj.getJwkMaxAgeInSeconds());
    if (obj.getJwks() != null) {
      JsonArray array = new JsonArray();
      obj.getJwks().forEach(item -> array.add(item));
      json.put("jwks", array);
    }
  }
}
