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
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Data Object containing the list of certificates used during the attestation of this authenticator.
 */
@DataObject
@JsonGen(publicConverter = false)
public class AttestationCertificates {

  /**
   * The algorithm used for the public credential
   */
  private PublicKeyCredential alg;

  /**
   * The list of X509 certificates encoded as base64url.
   */
  private List<String> x5c;

  public AttestationCertificates() {
  }

  public AttestationCertificates(JsonObject json) {
    AttestationCertificatesConverter.fromJson(json, this);
  }

  public PublicKeyCredential getAlg() {
    return alg;
  }

  public AttestationCertificates setAlg(PublicKeyCredential alg) {
    this.alg = alg;
    return this;
  }

  public List<String> getX5c() {
    return x5c;
  }

  public AttestationCertificates setX5c(JsonArray x5c) {
    if (x5c == null) {
      this.x5c = null;
    } else {
      this.x5c = new ArrayList<>();
      for (int i = 0; i < x5c.size(); i++) {
        this.x5c.add(x5c.getString(i));
      }
    }
    return this;
  }

  public AttestationCertificates setX5c(List<String> x5c) {
    this.x5c = x5c;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    AttestationCertificatesConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
