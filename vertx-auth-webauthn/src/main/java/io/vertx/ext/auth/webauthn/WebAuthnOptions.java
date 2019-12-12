/*
 * Copyright 2019 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;

import java.util.HashSet;
import java.util.Set;

@DataObject(generateConverter = true)
public class WebAuthnOptions {

  private String origin;
  private Set<String> transports;

  private String rpName;
  private String rpId;
  private String rpIcon;

  private AuthenticatorAttachment authenticatorAttachment;
  private Boolean requireResidentKey;
  private UserVerification userVerification;

  private int timeout;
  private Attestation attestation;

  private Set<String> pubKeyCredParams;

  public int getChallengeLength() {
    return challengeLength;
  }

  public void setChallengeLength(int challengeLength) {
    this.challengeLength = challengeLength;
  }

  private int challengeLength = 32;

  public WebAuthnOptions() {
    init();
  }

  public WebAuthnOptions(JsonObject json) {
    super();
    WebAuthnOptionsConverter.fromJson(json, this);
  }

  // sensible defaults
  private void init() {
    timeout = -1;
    addPubKeyCredParam("ES256");
    addPubKeyCredParam("RS256");
    addTransport("usb");
    addTransport("nfc");
    addTransport("ble");
    addTransport("internal");
  }

  public String getRpName() {
    return rpName;
  }

  public WebAuthnOptions setRpName(String rpName) {
    this.rpName = rpName;
    return this;
  }

  public String getRpId() {
    return rpId;
  }

  public WebAuthnOptions setRpId(String rpId) {
    this.rpId = rpId;
    return this;
  }

  public String getOrigin() {
    return origin;
  }

  public WebAuthnOptions setOrigin(String origin) {
    this.origin = origin;
    return this;
  }

  public String getRpIcon() {
    return rpIcon;
  }

  public WebAuthnOptions setRpIcon(String rpIcon) {
    this.rpIcon = rpIcon;
    return this;
  }

  public Set<String> getTransports() {
    return transports;
  }

  public WebAuthnOptions setTransports(Set<String> transports) {
    this.transports = transports;
    return this;
  }

  public WebAuthnOptions addTransport(String transport) {
    if (transports == null) {
      transports = new HashSet<>();
    }

    this.transports.add(transport);
    return this;
  }

  public Attestation getAttestation() {
    return attestation;
  }

  public WebAuthnOptions setAttestation(Attestation attestation) {
    this.attestation = attestation;
    return this;
  }

  public Set<String> getPubKeyCredParams() {
    return pubKeyCredParams;
  }

  public WebAuthnOptions addPubKeyCredParam(String pubKeyCredParam) {
    if (this.pubKeyCredParams == null) {
      this.pubKeyCredParams = new HashSet<>();
    }
    this.pubKeyCredParams.add(pubKeyCredParam);
    return this;
  }

  public WebAuthnOptions setPubKeyCredParams(Set<String> pubKeyCredParams) {
    this.pubKeyCredParams = pubKeyCredParams;
    return this;
  }

  public AuthenticatorAttachment getAuthenticatorAttachment() {
    return authenticatorAttachment;
  }

  public WebAuthnOptions setAuthenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
    this.authenticatorAttachment = authenticatorAttachment;
    return this;
  }

  public Boolean getRequireResidentKey() {
    return requireResidentKey;
  }

  public WebAuthnOptions setRequireResidentKey(Boolean requireResidentKey) {
    this.requireResidentKey = requireResidentKey;
    return this;
  }

  public UserVerification getUserVerification() {
    return userVerification;
  }

  public WebAuthnOptions setUserVerification(UserVerification userVerification) {
    this.userVerification = userVerification;
    return this;
  }

  public int getTimeout() {
    return timeout;
  }

  public WebAuthnOptions setTimeout(int timeout) {
    this.timeout = timeout;
    return this;
  }

  // extras

  public JsonObject getRpObject() {
    if (rpName == null) {
      throw new IllegalStateException("rpName is required but not set!");
    }

    JsonObject rp = new JsonObject()
      .put("name", rpName);

    if (rpId != null) {
      rp.put("id", rpId);
    }

    if (rpIcon != null) {
      rp.put("icon", rpIcon);
    }

    return rp;
  }

  public JsonObject getAuthenticatorSelection() {
    JsonObject json = null;
    if (authenticatorAttachment != null) {
      if (json == null) {
        json = new JsonObject();
      }
      json.put("authenticatorAttachment", authenticatorAttachment.toString());
    }
    if (requireResidentKey != null) {
      if (json == null) {
        json = new JsonObject();
      }
      json.put("requireResidentKey", requireResidentKey);
    }
    if (userVerification != null) {
      if (json == null) {
        json = new JsonObject();
      }
      json.put("userVerification", userVerification.toString());
    }

    return json;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    WebAuthnOptionsConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encodePrettily();
  }
}
