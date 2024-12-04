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
package io.vertx.ext.auth.webauthn4j;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

import java.util.UUID;

import static io.vertx.ext.auth.impl.Codec.base64UrlDecode;

/**
 * Data Object representing an authenticator at rest.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class Authenticator {

  /**
   * The username linked to this authenticator
   */
  private String username;

  /**
   * The type of key (must be "public-key")
   */
  private String type = "public-key";

  /**
   * The non user identifiable id for the authenticator
   */
  private String credID;

  /**
   * The public key associated with this authenticator.
   * This is actually a Base64-URL-encoded CBOR of the COSE_Key public key as described in https://datatracker.ietf.org/doc/html/rfc9052#section-7
   * Also see https://w3c.github.io/webauthn/#sctn-attested-credential-data
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

  private int flags;

  public Authenticator() {
  }

  public Authenticator(JsonObject json) {
    AuthenticatorConverter.fromJson(json, this);
  }

  public String getUsername() {
    return username;
  }

  public Authenticator setUsername(String username) {
    this.username = username;
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

  public int getFlags() {
    return flags;
  }

  public Authenticator setFlags(int flags) {
    this.flags = flags;
    return this;
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
}
