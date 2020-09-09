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

import java.util.ArrayList;
import java.util.List;

import static io.vertx.ext.auth.webauthn.AuthenticatorTransport.*;
import static io.vertx.ext.auth.webauthn.PublicKeyCredential.*;
import static io.vertx.ext.auth.webauthn.UserVerificationRequirement.*;

@DataObject(generateConverter = true)
public class WebAuthnOptions {

  private String origin;
  private List<AuthenticatorTransport> transports;

  private RelayParty relayParty;

  private AuthenticatorAttachment authenticatorAttachment;
  private boolean requireResidentKey;
  private UserVerificationRequirement userVerificationRequirement;

  private Integer timeout;
  private Attestation attestation;

  // Needs to be a list, order is important
  private List<PublicKeyCredential> pubKeyCredParams;

  private int challengeLength;
  private JsonObject extensions;

  public WebAuthnOptions() {
    init();
  }

  public WebAuthnOptions(JsonObject json) {
    super();
    WebAuthnOptionsConverter.fromJson(json, this);
  }

  // sensible defaults
  private void init() {
    userVerificationRequirement = DISCOURAGED;
    requireResidentKey = false;
    extensions = new JsonObject()
      .put("txAuthSimple", "");

    timeout = 60_000;
    challengeLength = 64;
    // Support FIDO2 devices, MACOSX, default
    addPubKeyCredParam(ES256);
    // Support Windows devices (Hello)
    addPubKeyCredParam(RS256);
    // all known transports
    addTransport(USB);
    addTransport(NFC);
    addTransport(BLE);
    addTransport(INTERNAL);
  }

  public RelayParty getRelayParty() {
    return relayParty;
  }

  public WebAuthnOptions setRelayParty(RelayParty relayParty) {
    if (relayParty.getName() == null) {
      throw new IllegalArgumentException("RelayParty name cannot be null");
    }

    this.relayParty = relayParty;
    return this;
  }

  public List<AuthenticatorTransport> getTransports() {
    return transports;
  }

  public WebAuthnOptions setTransports(List<AuthenticatorTransport> transports) {
    this.transports = transports;
    return this;
  }

  public WebAuthnOptions addTransport(AuthenticatorTransport transport) {
    if (transports == null) {
      transports = new ArrayList<>();
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

  public List<PublicKeyCredential> getPubKeyCredParams() {
    return pubKeyCredParams;
  }

  public WebAuthnOptions addPubKeyCredParam(PublicKeyCredential pubKeyCredParam) {
    if (pubKeyCredParams == null) {
      pubKeyCredParams = new ArrayList<>();
    }
    if (!pubKeyCredParams.contains(pubKeyCredParam)) {
      pubKeyCredParams.add(pubKeyCredParam);
    }
    return this;
  }

  public WebAuthnOptions setPubKeyCredParams(List<PublicKeyCredential> pubKeyCredParams) {
    if (pubKeyCredParams.size() == 0) {
      throw new IllegalArgumentException("PubKeyCredParams must have at least 1 element");
    }
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

  public boolean getRequireResidentKey() {
    return requireResidentKey;
  }

  public WebAuthnOptions setRequireResidentKey(boolean requireResidentKey) {
    this.requireResidentKey = requireResidentKey;
    return this;
  }

  public UserVerificationRequirement getUserVerification() {
    return userVerificationRequirement;
  }

  public WebAuthnOptions setUserVerification(UserVerificationRequirement userVerificationRequirement) {
    this.userVerificationRequirement = userVerificationRequirement;
    return this;
  }

  public Integer getTimeout() {
    return timeout;
  }

  public WebAuthnOptions setTimeout(Integer timeout) {
    if (timeout != null) {
      if (timeout < 0) {
        throw new IllegalArgumentException("Timeout must be >= 0");
      }
    }
    this.timeout = timeout;
    return this;
  }

  public JsonObject getAuthenticatorSelection() {
    JsonObject json = new JsonObject()
      .put("requireResidentKey", requireResidentKey);

    if (authenticatorAttachment != null) {
      json.put("authenticatorAttachment", authenticatorAttachment.toString());
    }
    if (userVerificationRequirement != null) {
      json.put("userVerification", userVerificationRequirement.toString());
    }

    return json;
  }

  public int getChallengeLength() {
    return challengeLength;
  }

  public WebAuthnOptions setChallengeLength(int challengeLength) {
    if (challengeLength < 32) {
      throw new IllegalArgumentException("Challenge length must be >= 32");
    }
    this.challengeLength = challengeLength;
    return this;
  }

  public JsonObject getExtensions() {
    return extensions;
  }

  public WebAuthnOptions setExtensions(JsonObject extensions) {
    this.extensions = extensions;
    return this;
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
