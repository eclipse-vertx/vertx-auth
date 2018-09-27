package io.vertx.ext.auth.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter for {@link io.vertx.ext.auth.oauth2.OAuth2ClientOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.oauth2.OAuth2ClientOptions} original class using Vert.x codegen.
 */
public class OAuth2ClientOptionsConverter {

  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, OAuth2ClientOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authorizationPath":
          if (member.getValue() instanceof String) {
            obj.setAuthorizationPath((String)member.getValue());
          }
          break;
        case "clientID":
          if (member.getValue() instanceof String) {
            obj.setClientID((String)member.getValue());
          }
          break;
        case "clientSecret":
          if (member.getValue() instanceof String) {
            obj.setClientSecret((String)member.getValue());
          }
          break;
        case "clientSecretParameterName":
          if (member.getValue() instanceof String) {
            obj.setClientSecretParameterName((String)member.getValue());
          }
          break;
        case "extraParameters":
          if (member.getValue() instanceof JsonObject) {
            obj.setExtraParameters(((JsonObject)member.getValue()).copy());
          }
          break;
        case "flow":
          if (member.getValue() instanceof String) {
            obj.setFlow(io.vertx.ext.auth.oauth2.OAuth2FlowType.valueOf((String)member.getValue()));
          }
          break;
        case "headers":
          if (member.getValue() instanceof JsonObject) {
            obj.setHeaders(((JsonObject)member.getValue()).copy());
          }
          break;
        case "introspectionPath":
          if (member.getValue() instanceof String) {
            obj.setIntrospectionPath((String)member.getValue());
          }
          break;
        case "jwkPath":
          if (member.getValue() instanceof String) {
            obj.setJwkPath((String)member.getValue());
          }
          break;
        case "jwtOptions":
          if (member.getValue() instanceof JsonObject) {
            obj.setJWTOptions(new io.vertx.ext.jwt.JWTOptions((JsonObject)member.getValue()));
          }
          break;
        case "logoutPath":
          if (member.getValue() instanceof String) {
            obj.setLogoutPath((String)member.getValue());
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
        case "revocationPath":
          if (member.getValue() instanceof String) {
            obj.setRevocationPath((String)member.getValue());
          }
          break;
        case "scopeSeparator":
          if (member.getValue() instanceof String) {
            obj.setScopeSeparator((String)member.getValue());
          }
          break;
        case "site":
          if (member.getValue() instanceof String) {
            obj.setSite((String)member.getValue());
          }
          break;
        case "tokenPath":
          if (member.getValue() instanceof String) {
            obj.setTokenPath((String)member.getValue());
          }
          break;
        case "useBasicAuthorizationHeader":
          if (member.getValue() instanceof Boolean) {
            obj.setUseBasicAuthorizationHeader((Boolean)member.getValue());
          }
          break;
        case "userAgent":
          if (member.getValue() instanceof String) {
            obj.setUserAgent((String)member.getValue());
          }
          break;
        case "userInfoParameters":
          if (member.getValue() instanceof JsonObject) {
            obj.setUserInfoParameters(((JsonObject)member.getValue()).copy());
          }
          break;
        case "userInfoPath":
          if (member.getValue() instanceof String) {
            obj.setUserInfoPath((String)member.getValue());
          }
          break;
        case "validateIssuer":
          if (member.getValue() instanceof Boolean) {
            obj.setValidateIssuer((Boolean)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(OAuth2ClientOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(OAuth2ClientOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthorizationPath() != null) {
      json.put("authorizationPath", obj.getAuthorizationPath());
    }
    if (obj.getClientID() != null) {
      json.put("clientID", obj.getClientID());
    }
    if (obj.getClientSecret() != null) {
      json.put("clientSecret", obj.getClientSecret());
    }
    if (obj.getClientSecretParameterName() != null) {
      json.put("clientSecretParameterName", obj.getClientSecretParameterName());
    }
    if (obj.getExtraParameters() != null) {
      json.put("extraParameters", obj.getExtraParameters());
    }
    if (obj.getFlow() != null) {
      json.put("flow", obj.getFlow().name());
    }
    if (obj.getHeaders() != null) {
      json.put("headers", obj.getHeaders());
    }
    if (obj.getIntrospectionPath() != null) {
      json.put("introspectionPath", obj.getIntrospectionPath());
    }
    if (obj.getJwkPath() != null) {
      json.put("jwkPath", obj.getJwkPath());
    }
    if (obj.getLogoutPath() != null) {
      json.put("logoutPath", obj.getLogoutPath());
    }
    if (obj.getRevocationPath() != null) {
      json.put("revocationPath", obj.getRevocationPath());
    }
    if (obj.getScopeSeparator() != null) {
      json.put("scopeSeparator", obj.getScopeSeparator());
    }
    if (obj.getSite() != null) {
      json.put("site", obj.getSite());
    }
    if (obj.getTokenPath() != null) {
      json.put("tokenPath", obj.getTokenPath());
    }
    json.put("useBasicAuthorizationHeader", obj.isUseBasicAuthorizationHeader());
    if (obj.getUserAgent() != null) {
      json.put("userAgent", obj.getUserAgent());
    }
    if (obj.getUserInfoParameters() != null) {
      json.put("userInfoParameters", obj.getUserInfoParameters());
    }
    if (obj.getUserInfoPath() != null) {
      json.put("userInfoPath", obj.getUserInfoPath());
    }
    json.put("validateIssuer", obj.isValidateIssuer());
  }
}
