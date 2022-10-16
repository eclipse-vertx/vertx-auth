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
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;

@DataObject(generateConverter = true)
public class WebAuthnCredentials implements Credentials {

  private String challenge;
  private JsonObject webauthn;
  private String username;
  private String userId;
  private String origin;
  private String domain;

  public WebAuthnCredentials() {}

  public WebAuthnCredentials(JsonObject json) {
    WebAuthnCredentialsConverter.fromJson(json, this);
  }

  public String getChallenge() {
    return challenge;
  }

  public WebAuthnCredentials setChallenge(String challenge) {
    this.challenge = challenge;
    return this;
  }

  public JsonObject getWebauthn() {
    return webauthn;
  }

  public WebAuthnCredentials setWebauthn(JsonObject webauthn) {
    this.webauthn = webauthn;
    return this;
  }

  public String getUsername() {
    return username;
  }

  public WebAuthnCredentials setUsername(String username) {
    this.username = username;
    return this;
  }

  public String getOrigin() {
    return origin;
  }

  public WebAuthnCredentials setOrigin(String origin) {
    this.origin = origin;
    return this;
  }

  public String getDomain() {
    return domain;
  }

  public WebAuthnCredentials setDomain(String domain) {
    this.domain = domain;
    return this;
  }

  public String getUserId() {
    return userId;
  }

  public WebAuthnCredentials setUserId(String userId) {
    this.userId = userId;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (challenge == null || challenge.length() == 0) {
      throw new CredentialValidationException("Challenge cannot be null or empty");
    }

    if (webauthn == null) {
      throw new CredentialValidationException("webauthn cannot be null");
    }

    if (!webauthn.containsKey("id") || !webauthn.containsKey("rawId") || !webauthn.containsKey("response")) {
      throw new CredentialValidationException("Invalid webauthn JSON, missing one of {id, rawId, response}");
    }

    if (!webauthn.getString("id").equals(webauthn.getString("rawId"))) {
      throw new CredentialValidationException("Invalid webauthn {id} not base64url encoded");
    }

    try {
      JsonObject response = webauthn.getJsonObject("response");
      // response.clientDataJSON must be always present
      if (!response.containsKey("clientDataJSON")) {
        throw new CredentialValidationException("Missing webauthn.response.clientDataJSON");
      }
      // if response.userHandle is present it should be a String
      if (response.containsKey("userHandle")) {
        if (!(response.getValue("userHandle") instanceof String)) {
          throw new CredentialValidationException("webauthn.response.userHandle must be String");
        }
      }
    } catch (ClassCastException e) {
      throw new CredentialValidationException("webauthn.response must be JSON");
    }

    // Username may be null once the system has stored it once.
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    WebAuthnCredentialsConverter.toJson(this, json);
    return json;
  }
}
