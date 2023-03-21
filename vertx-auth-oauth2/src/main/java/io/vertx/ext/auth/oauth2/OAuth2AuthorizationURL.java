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
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TypeSafe DataObject for passing needed parameters for {@link OAuth2Auth#authorizeURL(OAuth2AuthorizationURL)}
 *
 * @author <a href="mailto:lazarbulic@gmail.com">Lazar Bulic</a>
 */
@DataObject
public class OAuth2AuthorizationURL {

  private List<String> scopes;
  private String state;
  private Map<String, String> additionalParameters;

  /**
   * Default constructor
   */
  public OAuth2AuthorizationURL() {
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public OAuth2AuthorizationURL(JsonObject json) {
    setState(json.getString("state"));
    JsonArray scopes = json.getJsonArray("scopes");
    if (scopes != null) {
      scopes.forEach(scope -> addScope((String) scope));
    }
    JsonObject additionalParameters = json.getJsonObject("additionalParameters");
    if (additionalParameters != null) {
      additionalParameters.forEach(entry -> putAdditionalParameter(entry.getKey(), (String) entry.getValue()));
    }
  }

  /**
   * Constructor to create an options from an existing options
   *
   * @param other the existing one to clone
   */
  public OAuth2AuthorizationURL(OAuth2AuthorizationURL other) {
    this.state = other.state;

    if (other.scopes != null) {
      this.scopes = new ArrayList<>(other.scopes);
    }
    if (other.additionalParameters != null) {
      this.additionalParameters = new HashMap<>(other.additionalParameters);
    }
  }

  /**
   * Get the redirect URI
   *
   * @return the redirectUri
   */
  public String getRedirectUri() {
    return additionalParameters == null ?
      null :
      getAdditionalParameters().get("redirect_uri");
  }

  /**
   * Set the redirect URI
   *
   * @param redirectUri the redirectUri to set
   * @return self
   */
  public OAuth2AuthorizationURL setRedirectUri(String redirectUri) {
    // empty redirects are not allowed and should be considered as null
    putAdditionalParameter("redirect_uri", "".equals(redirectUri) ? null : redirectUri);
    return this;
  }

  /**
   * Get the scopes
   *
   * @return the scopes
   */
  public List<String> getScopes() {
    return scopes;
  }

  /**
   * Set the scopes
   *
   * @param scopes the scopes to set
   * @return self
   */
  public OAuth2AuthorizationURL setScopes(List<String> scopes) {
    this.scopes = scopes;
    return this;
  }

  /**
   * Add a scope
   *
   * @param scope the scope to add
   * @return self
   */
  public OAuth2AuthorizationURL addScope(String scope) {
    if (this.scopes == null) {
      this.scopes = new ArrayList<>();
    }
    this.scopes.add(scope);
    return this;
  }

  /**
   * Get the state
   *
   * @return the state
   */
  public String getState() {
    return state;
  }

  /**
   * Set the state
   *
   * @param state the state to set
   * @return self
   */
  public OAuth2AuthorizationURL setState(String state) {
    this.state = state;
    return this;
  }

  /**
   * PKCE code challenge
   */
  public String getCodeChallenge() {
    return additionalParameters == null ?
      null :
      getAdditionalParameters().get("code_challenge");
  }

  /**
   * PKCE code challenge
   */
  public OAuth2AuthorizationURL setCodeChallenge(String codeChallenge) {
    putAdditionalParameter("code_challenge", codeChallenge);
    return this;
  }

  /**
   * PKCE code challenge method
   */
  public String getCodeChallengeMethod() {
    return additionalParameters == null ?
      null :
      getAdditionalParameters()
      .get("code_challenge_method");
  }

  /**
   * PKCE code challenge method
   */
  public OAuth2AuthorizationURL setCodeChallengeMethod(String codeChallengeMethod) {
    putAdditionalParameter("code_challenge_method", codeChallengeMethod);
    return this;
  }

  /**
   * Hint on kind of IdP prompt
   */
  public String getPrompt() {
    return additionalParameters == null ?
      null :
      getAdditionalParameters()
      .get("prompt");
  }

  /**
   * Hint on kind of IdP prompt
   */
  public OAuth2AuthorizationURL setPrompt(String prompt) {
    putAdditionalParameter("prompt", prompt);
    return this;
  }

  /**
   * Hint on login name for IdP UI
   */
  public String getLoginHint() {
    return additionalParameters == null ?
      null :
      getAdditionalParameters()
      .get("login_hint");
  }

  /**
   * Hint on login name for IdP UI
   */
  public OAuth2AuthorizationURL setLoginHint(String loginHint) {
    putAdditionalParameter("login_hint", loginHint);
    return this;
  }

  /**
   * Get the additional parameters
   *
   * @return the additionalParameters
   */
  public Map<String, String> getAdditionalParameters() {
    return additionalParameters;
  }

  /**
   * Set the additional parameters
   *
   * @param additionalParameters the additionalParameters to set. Both key and value should be in final format that is expected by the provider.
   *                             Example: "ui_locales" -> "fr-CA fr en"
   * @return self
   */
  public OAuth2AuthorizationURL setAdditionalParameters(Map<String, String> additionalParameters) {
    this.additionalParameters = additionalParameters;
    return this;
  }

  /**
   * Add an additional parameter
   *
   * @param key   the key of the parameter. Should be in final format that is expected by the provider. Example: "ui_locales"
   * @param value the value of the parameter. Should be in final format that is expected by the provider. Example: "fr-CA fr en"
   * @return self
   */
  public OAuth2AuthorizationURL putAdditionalParameter(String key, String value) {
    if (value == null) {
      if (this.additionalParameters != null) {
        this.additionalParameters.remove(key);
      }
      return this;
    }

    if (this.additionalParameters == null) {
      this.additionalParameters = new HashMap<>();
    }
    this.additionalParameters.put(key, value);
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();

    if (state != null) {
      json.put("state", state);
    }
    if (scopes != null) {
      json.put("scopes", new JsonArray(scopes));
    }
    if (additionalParameters != null) {
      json.put("additionalParameters", new JsonObject((Map) additionalParameters));
    }
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

}
