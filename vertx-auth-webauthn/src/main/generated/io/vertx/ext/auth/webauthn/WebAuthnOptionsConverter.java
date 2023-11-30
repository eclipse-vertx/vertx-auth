package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.impl.JsonUtil;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.WebAuthnOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.WebAuthnOptions} original class using Vert.x codegen.
 */
public class WebAuthnOptionsConverter {


  private static final Base64.Decoder BASE64_DECODER = JsonUtil.BASE64_DECODER;
  private static final Base64.Encoder BASE64_ENCODER = JsonUtil.BASE64_ENCODER;

   static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthnOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "relyingParty":
          if (member.getValue() instanceof JsonObject) {
            obj.setRelyingParty(new io.vertx.ext.auth.webauthn.RelyingParty((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "transports":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.webauthn.AuthenticatorTransport> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add(io.vertx.ext.auth.webauthn.AuthenticatorTransport.valueOf((String)item));
            });
            obj.setTransports(list);
          }
          break;
        case "attestation":
          if (member.getValue() instanceof String) {
            obj.setAttestation(io.vertx.ext.auth.webauthn.Attestation.valueOf((String)member.getValue()));
          }
          break;
        case "residentKey":
          if (member.getValue() instanceof String) {
            obj.setResidentKey(io.vertx.ext.auth.webauthn.ResidentKey.valueOf((String)member.getValue()));
          }
          break;
        case "pubKeyCredParams":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<io.vertx.ext.auth.webauthn.PublicKeyCredential> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add(io.vertx.ext.auth.webauthn.PublicKeyCredential.valueOf((String)item));
            });
            obj.setPubKeyCredParams(list);
          }
          break;
        case "authenticatorAttachment":
          if (member.getValue() instanceof String) {
            obj.setAuthenticatorAttachment(io.vertx.ext.auth.webauthn.AuthenticatorAttachment.valueOf((String)member.getValue()));
          }
          break;
        case "requireResidentKey":
          if (member.getValue() instanceof Boolean) {
            obj.setRequireResidentKey((Boolean)member.getValue());
          }
          break;
        case "userVerification":
          if (member.getValue() instanceof String) {
            obj.setUserVerification(io.vertx.ext.auth.webauthn.UserVerification.valueOf((String)member.getValue()));
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
        case "rootCrls":
          if (member.getValue() instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list =  new java.util.ArrayList<>();
            ((Iterable<Object>)member.getValue()).forEach( item -> {
              if (item instanceof String)
                list.add((String)item);
            });
            obj.setRootCrls(list);
          }
          break;
        case "relaxedSafetyNetIntegrityVeridict":
          if (member.getValue() instanceof Boolean) {
            obj.setRelaxedSafetyNetIntegrityVeridict((Boolean)member.getValue());
          }
          break;
      }
    }
  }

   static void toJson(WebAuthnOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

   static void toJson(WebAuthnOptions obj, java.util.Map<String, Object> json) {
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
    if (obj.getRequireResidentKey() != null) {
      json.put("requireResidentKey", obj.getRequireResidentKey());
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
  }
}
