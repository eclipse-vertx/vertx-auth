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
public class WebAuthNOptions {

  private String realmId;
  private String realm;
  private String realmDisplayName;
  private String realmIcon;
  private String attestation;
  private Set<String> pubKeyCredParams;
  private String origin;
  private Set<String> transports;

  public int getChallengeLength() {
    return challengeLength;
  }

  public void setChallengeLength(int challengeLength) {
    this.challengeLength = challengeLength;
  }

  private int challengeLength = 32;

  public WebAuthNOptions() {
    init();
  }

  public WebAuthNOptions(JsonObject json) {
    super();
    WebAuthNOptionsConverter.fromJson(json, this);
  }

  // sensible defaults
  private void init() {
    setAttestation("none");
    addPubKeyCredParam("ES256");
    addPubKeyCredParam("RS256");
    addTransport("usb");
    addTransport("nfc");
    addTransport("ble");
    addTransport("internal");
  }

  public String getRealm() {
    return realm;
  }

  public WebAuthNOptions setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public String getRealmId() {
    return realmId;
  }

  public WebAuthNOptions setRealmId(String realmId) {
    this.realmId = realmId;
    return this;
  }

  public String getOrigin() {
    return origin;
  }

  public WebAuthNOptions setOrigin(String origin) {
    this.origin = origin;
    return this;
  }

  public String getRealmDisplayName() {
    return realmDisplayName;
  }

  public WebAuthNOptions setRealmDisplayName(String realmDisplayName) {
    this.realmDisplayName = realmDisplayName;
    return this;
  }

  public String getRealmIcon() {
    return realmIcon;
  }

  public WebAuthNOptions setRealmIcon(String realmIcon) {
    this.realmIcon = realmIcon;
    return this;
  }

  public Set<String> getTransports() {
    return transports;
  }

  public WebAuthNOptions setTransports(Set<String> transports) {
    this.transports = transports;
    return this;
  }

  public WebAuthNOptions addTransport(String transport) {
    if (transports == null) {
      transports = new HashSet<>();
    }

    this.transports.add(transport);
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    WebAuthNOptionsConverter.toJson(this, json);
    return json;
  }

  public String getAttestation() {
    return attestation;
  }

  public WebAuthNOptions setAttestation(String attestation) {
    this.attestation = attestation;
    return this;
  }

  public Set<String> getPubKeyCredParams() {
    return pubKeyCredParams;
  }

  public WebAuthNOptions addPubKeyCredParam(String pubKeyCredParam) {
    if (this.pubKeyCredParams == null) {
      this.pubKeyCredParams = new HashSet<>();
    }
    this.pubKeyCredParams.add(pubKeyCredParam);
    return this;
  }

  public WebAuthNOptions setPubKeyCredParams(Set<String> pubKeyCredParams) {
    this.pubKeyCredParams = pubKeyCredParams;
    return this;
  }

  @Override
  public String toString() {
    return toJson().encodePrettily();
  }
}
