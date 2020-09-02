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
import io.vertx.ext.auth.authentication.Credentials;

import java.util.Map;

/**
 * Credentials specific to the {@link OAuth2Auth} provider
 *
 * @author <a href="mailto:pmlopes@gmail.com">Paulo Lopes</a>
 */
@DataObject
public class Oauth2Credentials implements Credentials {

  private String code;
  private String redirectUri;
  // tokens can include other kind of generic data
  private JsonObject extra;

  public Oauth2Credentials() {
  }

  public Oauth2Credentials(JsonObject jsonObject) {
    for (Map.Entry<String, Object> member : jsonObject) {
      switch (member.getKey()) {
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

  public JsonObject getExtra() {
    return extra;
  }

  public Oauth2Credentials setExtra(JsonObject extra) {
    this.extra = extra;
    return this;
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();

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
    OAuth2FlowType flow = (OAuth2FlowType) arg;
    // when there's no access token, validation shall be performed according to each flow
    switch (flow) {
      case AUTH_CODE:
        if (code == null || code.length() == 0) {
          throw new CredentialValidationException("code cannot be null or empty");
        }
        if (redirectUri != null && redirectUri.length() == 0) {
          throw new CredentialValidationException("redirectUri cannot be empty");
        }
        break;
    }
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
