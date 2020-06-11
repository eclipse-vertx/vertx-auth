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
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;

import java.util.Map;
import java.util.Objects;

/**
 * Credentials specific to the {@link OAuth2Auth} provider
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
@DataObject
public class Oauth2Credentials extends UsernamePasswordCredentials {

  private String accessToken;
  private String code;
  private String redirectUri;
  // tokens can include other kind of generic data
  private JsonObject extra;

  public Oauth2Credentials() {
    super();
  }

  public Oauth2Credentials(JsonObject jsonObject) {
    super(jsonObject);

    for (Map.Entry<String, Object> member : jsonObject) {
      switch (member.getKey()) {
        case "access_token":
          if (member.getValue() instanceof String) {
            setAccessToken((String) member.getValue());
          }
          break;
        case "code":
          if (member.getValue() instanceof String) {
            setCode((String) member.getValue());
          }
          break;
        case "redirect_uri":
          if (member.getValue() instanceof String) {
            setRedirectUri((String) member.getValue());
          }
          break;
        default:
          if (extra == null) {
            extra = new JsonObject();
          }
          extra.put(member.getKey(), member.getValue());
      }
    }
  }

  @Override
  public Oauth2Credentials setPassword(String password) {
    super.setPassword(password);
    return this;
  }

  @Override
  public Oauth2Credentials setUsername(String username) {
    super.setUsername(username);
    return this;
  }


  public String getAccessToken() {
    return accessToken;
  }

  public Oauth2Credentials setAccessToken(String accessToken) {
    this.accessToken = Objects.requireNonNull(accessToken);
    return this;
  }

  public String getCode() {
    return code;
  }

  public Oauth2Credentials setCode(String code) {
    this.code = Objects.requireNonNull(code);
    return this;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public Oauth2Credentials setRedirectUri(String redirectUri) {
    this.redirectUri = Objects.requireNonNull(redirectUri);
    return this;
  }

  public JsonObject getExtra() {
    return extra;
  }

  public Oauth2Credentials setExtra(JsonObject extra) {
    this.extra = Objects.requireNonNull(extra);
    return this;
  }

  public JsonObject toJson() {
    JsonObject json = super.toJson();
    if (getAccessToken() != null) {
      json.put("access_token", getAccessToken());
    }
    if (getCode() != null) {
      json.put("code", getCode());
    }
    if (getRedirectUri() != null) {
      json.put("redirect_uri", getRedirectUri());
    }
    if (extra != null) {
      json.mergeIn(extra);
    }
    return json;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (accessToken == null || accessToken.length() == 0) {
      OAuth2FlowType flow = (OAuth2FlowType) arg;
      // when there's no access token, validation shall be performed according to each flow
      switch (flow) {
        case PASSWORD:
          super.checkValid(null);
          break;
        case AUTH_CODE:
          if (code == null || code.length() == 0) {
            throw new CredentialValidationException("code cannot be null or empty");
          }
          if (redirectUri == null || redirectUri.length() == 0) {
            throw new CredentialValidationException("redirectUri cannot be null or empty");
          }
          break;
      }
    }
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
