package io.vertx.ext.auth.ldap;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.ldap.LdapAuthenticationOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.ldap.LdapAuthenticationOptions} original class using Vert.x codegen.
 */
public class LdapAuthenticationOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, LdapAuthenticationOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "authenticationMechanism":
          if (member.getValue() instanceof String) {
            obj.setAuthenticationMechanism((String)member.getValue());
          }
          break;
        case "authenticationQuery":
          if (member.getValue() instanceof String) {
            obj.setAuthenticationQuery((String)member.getValue());
          }
          break;
        case "referral":
          if (member.getValue() instanceof String) {
            obj.setReferral((String)member.getValue());
          }
          break;
        case "url":
          if (member.getValue() instanceof String) {
            obj.setUrl((String)member.getValue());
          }
          break;
      }
    }
  }

  public static void toJson(LdapAuthenticationOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(LdapAuthenticationOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAuthenticationMechanism() != null) {
      json.put("authenticationMechanism", obj.getAuthenticationMechanism());
    }
    if (obj.getAuthenticationQuery() != null) {
      json.put("authenticationQuery", obj.getAuthenticationQuery());
    }
    if (obj.getReferral() != null) {
      json.put("referral", obj.getReferral());
    }
    if (obj.getUrl() != null) {
      json.put("url", obj.getUrl());
    }
  }
}
