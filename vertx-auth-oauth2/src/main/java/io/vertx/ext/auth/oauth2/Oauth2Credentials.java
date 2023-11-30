/*
 * Copyright 2015 Red Hat, Inc.
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
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.JsonGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;

import java.util.ArrayList;
import java.util.List;

/**
 * Credentials specific to the {@link OAuth2Auth} provider
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class Oauth2Credentials implements Credentials {

  // swap code for token
  private String code;
  private String redirectUri;
  private String codeVerifier;
  // jwt-bearer
  // tokens can include other kind of generic data
  private JsonObject jwt;
  // or contain an assertion
  private String assertion;
  // password credentials
  private String password;
  private String username;
  // control state
  private List<String> scopes;
  private OAuth2FlowType flow;

  public Oauth2Credentials() {
  }

  public Oauth2Credentials(JsonObject json) {
    Oauth2CredentialsConverter.fromJson(json, this);
  }

  public String getCode() {
    return code;
  }

  public Oauth2Credentials setCode(String code) {
    this.code = code;
    return this;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public Oauth2Credentials setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
    return this;
  }

  public String getCodeVerifier() {
    return codeVerifier;
  }

  public Oauth2Credentials setCodeVerifier(String codeVerifier) {
    this.codeVerifier = codeVerifier;
    return this;
  }

  public List<String> getScopes() {
    return scopes;
  }

  public Oauth2Credentials addScope(String scope) {
    if (this.scopes == null) {
      this.scopes = new ArrayList<>();
    }
    this.scopes.add(scope);
    return this;
  }

  public Oauth2Credentials setScopes(List<String> scopes) {
    this.scopes = scopes;
    return this;
  }

  public JsonObject getJwt() {
    return jwt;
  }

  public Oauth2Credentials setJwt(JsonObject jwt) {
    this.jwt = jwt;
    return this;
  }

  public String getAssertion() {
    return assertion;
  }

  public Oauth2Credentials setAssertion(String assertion) {
    this.assertion = assertion;
    return this;
  }

  public String getPassword() {
    return password;
  }

  public Oauth2Credentials setPassword(String password) {
    this.password = password;
    return this;
  }

  public String getUsername() {
    return username;
  }

  public Oauth2Credentials setUsername(String username) {
    this.username = username;
    return this;
  }

  public OAuth2FlowType getFlow() {
    return flow;
  }

  public Oauth2Credentials setFlow(OAuth2FlowType flow) {
    this.flow = flow;
    return this;
  }

  @Override
  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    Oauth2CredentialsConverter.toJson(this, json);
    return json;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    OAuth2FlowType flow = (OAuth2FlowType) arg;
    if (flow == null) {
      throw new CredentialValidationException("flow cannot be null");
    }
    // when there's no access token, validation shall be performed according to each flow
    switch (flow) {
      case CLIENT:
        // no fields are required
        break;
      case AUTH_CODE:
        if (code == null || code.length() == 0) {
          throw new CredentialValidationException("code cannot be null or empty");
        }
        if (redirectUri != null && redirectUri.length() == 0) {
          throw new CredentialValidationException("redirectUri cannot be empty");
        }
        break;
      case AUTH_JWT:
        if (jwt == null) {
          throw new CredentialValidationException("json cannot be null");
        }
        break;
      case AAD_OBO:
        if (assertion == null || assertion.length() == 0) {
          throw new CredentialValidationException("assertion cannot be null or empty");
        }
        break;
      case PASSWORD:
        if (username == null || username.length() == 0) {
          throw new CredentialValidationException("username cannot be null or empty");
        }
        if (password == null || password.length() == 0) {
          throw new CredentialValidationException("password cannot be null or empty");
        }
        break;
    }
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
