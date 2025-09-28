/*
 * Copyright (c) 2025 Sanju Thomas
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

@DataObject
@JsonGen(publicConverter = false)
public class DCRResponse {

  /**
   * A system generated unique identifier.
   */
  private String id;

  /**
   * User given client identifier.
   */
  private String clientId;
  /**
   * Whether the client is currently enabled or not.
   */
  private boolean enabled;

  /**
   * Client authenticator type, by default it is client-secret.
   */
  private String clientAuthenticatorType;

  /**
   * Client secret for client_secret_post or client_secret_basic.
   */
  private String secret;

  /**
   * RegistrationAccessToken is used for subsequent communication with Keycloak to
   * GET or DELETE the client.
   */
  private String registrationAccessToken;

  public DCRResponse(JsonObject json) {
    DCRResponseConverter.fromJson(json, this);
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    DCRResponseConverter.toJson(this, json);
    return json;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean isEnabled) {
    this.enabled = isEnabled;
  }

  public String getClientAuthenticatorType() {
    return clientAuthenticatorType;
  }

  public void setClientAuthenticatorType(String clientAuthenticatorType) {
    this.clientAuthenticatorType = clientAuthenticatorType;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(String secret) {
    this.secret = secret;
  }

  public String getRegistrationAccessToken() {
    return registrationAccessToken;
  }

  public void setRegistrationAccessToken(String registrationAccessToken) {
    this.registrationAccessToken = registrationAccessToken;
  }
}