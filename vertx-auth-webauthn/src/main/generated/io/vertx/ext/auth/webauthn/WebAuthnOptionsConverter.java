package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Converter and mapper for {@link io.vertx.ext.auth.webauthn.WebAuthnOptions}.
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.webauthn.WebAuthnOptions} original class using Vert.x codegen.
 */
public class WebAuthnOptionsConverter {


  public static void fromJson(Iterable<java.util.Map.Entry<String, Object>> json, WebAuthnOptions obj) {
    for (java.util.Map.Entry<String, Object> member : json) {
      switch (member.getKey()) {
        case "attestation":
          if (member.getValue() instanceof String) {
            obj.setAttestation(io.vertx.ext.auth.webauthn.Attestation.valueOf((String)member.getValue()));
          }
          break;
        case "authenticatorAttachment":
          if (member.getValue() instanceof String) {
            obj.setAuthenticatorAttachment(io.vertx.ext.auth.webauthn.AuthenticatorAttachment.valueOf((String)member.getValue()));
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
        case "relyingParty":
          if (member.getValue() instanceof JsonObject) {
            obj.setRelyingParty(new io.vertx.ext.auth.webauthn.RelyingParty((io.vertx.core.json.JsonObject)member.getValue()));
          }
          break;
        case "requireResidentKey":
          if (member.getValue() instanceof Boolean) {
            obj.setRequireResidentKey((Boolean)member.getValue());
          }
          break;
        case "timeout":
          if (member.getValue() instanceof Number) {
            obj.setTimeout(((Number)member.getValue()).longValue());
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
        case "userVerification":
          if (member.getValue() instanceof String) {
            obj.setUserVerification(io.vertx.ext.auth.webauthn.UserVerificationRequirement.valueOf((String)member.getValue()));
          }
          break;
      }
    }
  }

  public static void toJson(WebAuthnOptions obj, JsonObject json) {
    toJson(obj, json.getMap());
  }

  public static void toJson(WebAuthnOptions obj, java.util.Map<String, Object> json) {
    if (obj.getAttestation() != null) {
      json.put("attestation", obj.getAttestation().name());
    }
    if (obj.getAuthenticatorAttachment() != null) {
      json.put("authenticatorAttachment", obj.getAuthenticatorAttachment().name());
    }
    json.put("challengeLength", obj.getChallengeLength());
    if (obj.getExtensions() != null) {
      json.put("extensions", obj.getExtensions());
    }
    if (obj.getPubKeyCredParams() != null) {
      JsonArray array = new JsonArray();
      obj.getPubKeyCredParams().forEach(item -> array.add(item.name()));
      json.put("pubKeyCredParams", array);
    }
    if (obj.getRelyingParty() != null) {
      json.put("relyingParty", obj.getRelyingParty().toJson());
    }
    json.put("requireResidentKey", obj.getRequireResidentKey());
    if (obj.getTimeout() != null) {
      json.put("timeout", obj.getTimeout());
    }
    if (obj.getTransports() != null) {
      JsonArray array = new JsonArray();
      obj.getTransports().forEach(item -> array.add(item.name()));
      json.put("transports", array);
    }
    if (obj.getUserVerification() != null) {
      json.put("userVerification", obj.getUserVerification().name());
    }
  }
}
