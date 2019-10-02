package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.WebAuthNOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.WebAuthNOptions} original class using Vert.x codegen.
 */
public class WebAuthNOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthNOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "attestation":
          if (member.getValue() instanceof String) {
            obj.setAttestation((String)member.getValue());
          }
          break;
        case "challengeLength":
          if (member.getValue() instanceof Number) {
            obj.setChallengeLength(((Number)member.getValue()).intValue());
          }
          break;
        case "origin":
          if (member.getValue() instanceof String) {
            obj.setOrigin((String)member.getValue());
          }
          break;
        case "pubKeyCredParams":
          if (member.getValue() instanceof JsonArray) {
            java.util.LinkedHashSet<java.lang.String> list =  new java.util.LinkedHashSet<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setPubKeyCredParams(list);
          }
          break;
        case "realm":
          if (member.getValue() instanceof String) {
            obj.setRealm((String)member.getValue());
          }
          break;
        case "realmDisplayName":
          if (member.getValue() instanceof String) {
            obj.setRealmDisplayName((String)member.getValue());
          }
          break;
        case "realmIcon":
          if (member.getValue() instanceof String) {
            obj.setRealmIcon((String)member.getValue());
          }
          break;
        case "transports":
          if (member.getValue() instanceof JsonArray) {
            java.util.LinkedHashSet<java.lang.String> list =  new java.util.LinkedHashSet<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setTransports(list);
          }
          break;
      }
    }
  }

  public static void toJson(WebAuthNOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(WebAuthNOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAttestation() != null) {
      json.put("attestation", obj.getAttestation());
    }
    json.put("challengeLength", obj.getChallengeLength());
    if (obj.getOrigin() != null) {
      json.put("origin", obj.getOrigin());
    }
    if (obj.getPubKeyCredParams() != null) {
      JsonArray array = new JsonArray();
      obj.getPubKeyCredParams().forEach(item -> array.add(item));
      json.put("pubKeyCredParams", array);
    }
    if (obj.getRealm() != null) {
      json.put("realm", obj.getRealm());
    }
    if (obj.getRealmDisplayName() != null) {
      json.put("realmDisplayName", obj.getRealmDisplayName());
    }
    if (obj.getRealmIcon() != null) {
      json.put("realmIcon", obj.getRealmIcon());
    }
    if (obj.getTransports() != null) {
      JsonArray array = new JsonArray();
      obj.getTransports().forEach(item -> array.add(item));
      json.put("transports", array);
    }
  }
}
