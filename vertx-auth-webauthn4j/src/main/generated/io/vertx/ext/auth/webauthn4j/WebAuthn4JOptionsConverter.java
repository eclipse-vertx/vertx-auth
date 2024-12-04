package io.vertx.ext.auth.webauthn4j;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions} original class using Vert.x codegen.
 */
public class WebAuthn4JOptionsConverter {

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthn4JOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "relyingParty":
          if (member.getValue() instanceof JsonObject) {
            obj.setRelyingParty(new io.vertx.ext.auth.webauthn4j.RelyingParty((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "transports":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.webauthn4j.AuthenticatorTransport> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add(io.vertx.ext.auth.webauthn4j.AuthenticatorTransport.valueOf((String)item));
            });
            obj.setTransports(list);
          }
          break;
        case "attestation":
          if (member.getValue() instanceof String) {
            obj.setAttestation(io.vertx.ext.auth.webauthn4j.Attestation.valueOf((String)member.getValue()));
          }
          break;
        case "residentKey":
          if (member.getValue() instanceof String) {
            obj.setResidentKey(io.vertx.ext.auth.webauthn4j.ResidentKey.valueOf((String)member.getValue()));
          }
          break;
        case "pubKeyCredParams":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.webauthn4j.COSEAlgorithm> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add(io.vertx.ext.auth.webauthn4j.COSEAlgorithm.valueOf((String)item));
            });
            obj.setPubKeyCredParams(list);
          }
          break;
        case "authenticatorAttachment":
          if (member.getValue() instanceof String) {
            obj.setAuthenticatorAttachment(io.vertx.ext.auth.webauthn4j.AuthenticatorAttachment.valueOf((String)member.getValue()));
          }
          break;
        case "requireResidentKey":
          if (member.getValue() instanceof Boolean) {
            obj.setRequireResidentKey((Boolean)member.getValue());
          }
          break;
        case "userVerification":
          if (member.getValue() instanceof String) {
            obj.setUserVerification(io.vertx.ext.auth.webauthn4j.UserVerification.valueOf((String)member.getValue()));
          }
          break;
        case "timeoutInMilliseconds":
          if (member.getValue() instanceof Number) {
            obj.setTimeoutInMilliseconds(((Number)member.getValue()).longValue());
          }
          break;
        case "challengeLength":
          if (member.getValue() instanceof Number) {
            obj.setChallengeLength(((Number)member.getValue()).intValue());
          }
          break;
        case "extensions":
          if (member.getValue() instanceof JsonObject) {
            obj.setExtensions(((JsonObject)member.getValue()).copy());
          }
          break;
        case "rootCertificates":
          if (member.getValue() instanceof JsonObject) {
            java.util.Map<String, java.lang.String> map = new java.util.LinkedHashMap<>();
            ((Iterable<java.util.Map.Entry<String, Object>>)member.getValue()).forEach(entry -> {
              if (entry.getValue() instanceof String)
                map.put(entry.getKey(), (String)entry.getValue());
            });
            obj.setRootCertificates(map);
          }
          break;
        case "relaxedSafetyNetIntegrityVeridict":
          if (member.getValue() instanceof Boolean) {
            obj.setRelaxedSafetyNetIntegrityVeridict((Boolean)member.getValue());
          }
          break;
        case "useMetadata":
          if (member.getValue() instanceof Boolean) {
            obj.setUseMetadata((Boolean)member.getValue());
          }
          break;
        case "userPresenceRequired":
          if (member.getValue() instanceof Boolean) {
            obj.setUserPresenceRequired((Boolean)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(WebAuthn4JOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(WebAuthn4JOptions obj, java.util.Map<String, Object> json) {
    if (obj.getRelyingParty() != null) {
      json.put("relyingParty", obj.getRelyingParty().toJson());
    }
    if (obj.getTransports() != null) {
      JsonArray array = new JsonArray();
      obj.getTransports().forEach(item -> array.add(item.name()));
      json.put("transports", array);
    }
    if (obj.getAttestation() != null) {
      json.put("attestation", obj.getAttestation().name());
    }
    if (obj.getResidentKey() != null) {
      json.put("residentKey", obj.getResidentKey().name());
    }
    if (obj.getPubKeyCredParams() != null) {
      JsonArray array = new JsonArray();
      obj.getPubKeyCredParams().forEach(item -> array.add(item.name()));
      json.put("pubKeyCredParams", array);
    }
    if (obj.getAuthenticatorAttachment() != null) {
      json.put("authenticatorAttachment", obj.getAuthenticatorAttachment().name());
    }
    if (obj.getUserVerification() != null) {
      json.put("userVerification", obj.getUserVerification().name());
    }
    if (obj.getTimeoutInMilliseconds() != null) {
      json.put("timeoutInMilliseconds", obj.getTimeoutInMilliseconds());
    }
    json.put("challengeLength", obj.getChallengeLength());
    if (obj.getExtensions() != null) {
      json.put("extensions", obj.getExtensions());
    }
    json.put("relaxedSafetyNetIntegrityVeridict", obj.isRelaxedSafetyNetIntegrityVeridict());
    json.put("useMetadata", obj.isUseMetadata());
    json.put("userPresenceRequired", obj.isUserPresenceRequired());
  }
}
