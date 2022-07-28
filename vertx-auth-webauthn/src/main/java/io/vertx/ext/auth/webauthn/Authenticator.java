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
import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

import java.util.UUID;

import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;

/**
 * Data Object representing an authenticator at rest.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject(generateConverter = true)
public class Authenticator {

  /**
   * The username linked to this authenticator
   */
  private String userName;

  /**
   * The type of key (must be "public-key")
   */
  private String type = "public-key";

  /**
   * The non user identifiable id for the authenticator
   */
  private String credID;

  /**
   * The public key associated with this authenticator
   */
  private String publicKey;

  /**
   * The signature counter of the authenticator to prevent replay attacks
   */
  private long counter;

  private String aaguid;

  /**
   * The Authenticator attestation certificates object, a JSON like:
   * <pre>{@code
   *   {
   *     "alg": "string",
   *     "x5c": [
   *       "base64"
   *     ]
   *   }
   * }</pre>
   */
  private AttestationCertificates attestationCertificates;
  private String fmt;

  /**
   * The base64 url encoded user handle associated with this authenticator.
   */
  private String userId;

  public Authenticator() {}
  public Authenticator(JsonObject json) {
    AuthenticatorConverter.fromJson(json, this);
  }

  public String getUserName() {
    return userName;
  }

  public Authenticator setUserName(String userName) {
    this.userName = userName;
    return this;
  }

  public String getType() {
    return type;
  }

  public Authenticator setType(String type) {
    this.type = type;
    return this;
  }

  public String getCredID() {
    return credID;
  }

  public Authenticator setCredID(String credID) {
    this.credID = credID;
    return this;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public Authenticator setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public long getCounter() {
    return counter;
  }

  public Authenticator setCounter(long counter) {
    this.counter = counter;
    return this;
  }

  public Authenticator setAttestationCertificates(AttestationCertificates attestationCertificates) {
    this.attestationCertificates = attestationCertificates;
    return this;
  }

  public AttestationCertificates getAttestationCertificates() {
    return attestationCertificates;
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    AuthenticatorConverter.toJson(this, json);
    return json;
  }

  public static @Nullable UUID toUUID(String string) {
    if (string == null) {
      return null;
    }
    Buffer buffer = Buffer.buffer(base64UrlDecode(string));
    return new UUID(buffer.getLong(0), buffer.getLong(8));
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  public Authenticator setFmt(String fmt) {
    this.fmt = fmt;
    return this;
  }

  public String getFmt() {
    return fmt;
  }

  public Authenticator setAaguid(String aaguid) {
    this.aaguid = aaguid;
    return this;
  }

  public String getAaguid() {
    return aaguid;
  }

  public String getUserId() {
    return userId;
  }

  public Authenticator setUserId(String userId) {
    this.userId = userId;
    return this;
  }
}
