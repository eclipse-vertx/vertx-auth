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

import static io.vertx.ext.auth.webauthn.Attestation.*;
import static io.vertx.ext.auth.webauthn.AuthenticatorTransport.*;
import static io.vertx.ext.auth.webauthn.PublicKeyCredential.*;
import static io.vertx.ext.auth.webauthn.UserVerification.*;

/**
 * Configuration for the webauthn object
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class WebAuthnOptions {

  private List<AuthenticatorTransport> transports;

  private RelyingParty relyingParty;

  private AuthenticatorAttachment authenticatorAttachment;
  private boolean requireResidentKey;
  private UserVerification userVerification;

  private Long timeout;
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
    userVerification = DISCOURAGED;
    attestation = NONE;
    requireResidentKey = false;
    extensions = new JsonObject()
      .put("txAuthSimple", "");

    timeout = 60_000L;
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

  public RelyingParty getRelyingParty() {
    return relyingParty;
  }

  public WebAuthnOptions setRelyingParty(RelyingParty relyingParty) {
    if (relyingParty.getName() == null) {
      throw new IllegalArgumentException("RelyingParty name cannot be null");
    }

    this.relyingParty = relyingParty;
    return this;
  }

  public List<AuthenticatorTransport> getTransports() {
    return transports;
  }

  public WebAuthnOptions setTransports(List<AuthenticatorTransport> transports) {
    if (transports == null) {
      throw new IllegalArgumentException("transports cannot be null");
    }

    this.transports = transports;
    return this;
  }

  public WebAuthnOptions addTransport(AuthenticatorTransport transport) {
    if (transport == null) {
      throw new IllegalArgumentException("transport cannot be null");
    }

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
    if (userVerification == null) {
      throw new IllegalArgumentException("userVerification cannot be null");
    }
    this.attestation = attestation;
    return this;
  }

  public List<PublicKeyCredential> getPubKeyCredParams() {
    return pubKeyCredParams;
  }

  public WebAuthnOptions addPubKeyCredParam(PublicKeyCredential pubKeyCredParam) {
    if (pubKeyCredParam == null) {
      throw new IllegalArgumentException("pubKeyCredParam cannot be null");
    }

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

  public UserVerification getUserVerification() {
    return userVerification;
  }

  public WebAuthnOptions setUserVerification(UserVerification userVerification) {
    if (userVerification == null) {
      throw new IllegalArgumentException("userVerification cannot be null");
    }
    this.userVerification = userVerification;
    return this;
  }

  public Long getTimeout() {
    return timeout;
  }

  public WebAuthnOptions setTimeout(Long timeout) {
    if (timeout != null) {
      if (timeout < 0) {
        throw new IllegalArgumentException("Timeout must be >= 0");
      }
    }
    this.timeout = timeout;
    return this;
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
