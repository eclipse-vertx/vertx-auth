package io.vertx.ext.auth.webauthn4j;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn4j.Authenticator}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn4j.Authenticator} original class using Vert.x codegen.
 */
public class AuthenticatorConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, Authenticator obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "username":
          if (member.getValue() instanceof String) {
            obj.setUsername((String)member.getValue());
          }
          break;
        case "type":
          if (member.getValue() instanceof String) {
            obj.setType((String)member.getValue());
          }
          break;
        case "credID":
          if (member.getValue() instanceof String) {
            obj.setCredID((String)member.getValue());
          }
          break;
        case "publicKey":
          if (member.getValue() instanceof String) {
            obj.setPublicKey((String)member.getValue());
          }
          break;
        case "counter":
          if (member.getValue() instanceof Number) {
            obj.setCounter(((Number)member.getValue()).longValue());
          }
          break;
        case "attestationCertificates":
          if (member.getValue() instanceof JsonObject) {
            obj.setAttestationCertificates(new io.vertx.ext.auth.webauthn4j.AttestationCertificates((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "flags":
          if (member.getValue() instanceof Number) {
            obj.setFlags(((Number)member.getValue()).intValue());
          }
          break;
        case "fmt":
          if (member.getValue() instanceof String) {
            obj.setFmt((String)member.getValue());
          }
          break;
        case "aaguid":
          if (member.getValue() instanceof String) {
            obj.setAaguid((String)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(Authenticator obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(Authenticator obj, java.util.Map<String, Object> json) {
    if (obj.getUsername() != null) {
      json.put("username", obj.getUsername());
    }
    if (obj.getType() != null) {
      json.put("type", obj.getType());
    }
    if (obj.getCredID() != null) {
      json.put("credID", obj.getCredID());
    }
    if (obj.getPublicKey() != null) {
      json.put("publicKey", obj.getPublicKey());
    }
    json.put("counter", obj.getCounter());
    if (obj.getAttestationCertificates() != null) {
      json.put("attestationCertificates", obj.getAttestationCertificates().toJson());
    }
    json.put("flags", obj.getFlags());
    if (obj.getFmt() != null) {
      json.put("fmt", obj.getFmt());
    }
    if (obj.getAaguid() != null) {
      json.put("aaguid", obj.getAaguid());
    }
  }
}
