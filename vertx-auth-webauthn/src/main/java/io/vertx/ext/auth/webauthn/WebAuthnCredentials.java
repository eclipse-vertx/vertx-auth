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

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (challenge == null || challenge.length() == 0) {
      throw new CredentialValidationException("challenge cannot be null or empty");
    }

    if (webauthn == null) {
      throw new CredentialValidationException("webauthn cannot be null");
    }

    Object response = webauthn.getValue("response");

    if (!(response instanceof JsonObject)) {
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
