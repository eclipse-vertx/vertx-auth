/*
 * Copyright (c) 2011-2014 The original author or authors
 * ------------------------------------------------------
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 *     The Eclipse Public License is available at
 *     http://www.eclipse.org/legal/epl-v10.html
 *
 *     The Apache License v2.0 is available at
 *     http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.http.HttpClient;
import io.vertx.core.json.JsonObject;

/**
 * Options describing how an Keycloak {@link HttpClient} will make connections.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
public class KeycloakClientOptions extends OAuth2ClientOptions {

  private String userInfoPath;

  /**
   * Default constructor
   */
  public KeycloakClientOptions() {
    super();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public KeycloakClientOptions(KeycloakClientOptions other) {
    super(other);
    userInfoPath = other.getUserInfoPath();
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public KeycloakClientOptions(JsonObject json) {
    super(json);

    // translate keycloak json to oauth2 config
    if (json.containsKey("auth-server-url")) {
      setSite(json.getString("auth-server-url"));
    }

    if (json.containsKey("resource")) {
      setClientID(json.getString("resource"));
    }

    if (json.containsKey("credentials") && json.getJsonObject("credentials").containsKey("secret")) {
      setClientSecret(json.getJsonObject("credentials").getString("secret"));
    }

    if (json.containsKey("public-client") && json.getBoolean("public-client", false)) {
      setUseBasicAuthorizationHeader(true);
    }

    if (json.containsKey("realm")) {
      final String realm = json.getString("realm");

      setAuthorizationPath("/realms/" + realm + "/protocol/openid-connect/auth");
      setTokenPath("/realms/" + realm + "/protocol/openid-connect/token");
      setRevocationPath(null);
      setLogoutPath("/realms/" + realm + "/protocol/openid-connect/logout");
      setUserInfoPath("/realms/" + realm + "/protocol/openid-connect/userinfo");
    }

    if (json.containsKey("realm-public-key")) {
      setPublicKey(json.getString("realm-public-key"));
      setJwtToken(true);
    }
  }

  public String getUserInfoPath() {
    return userInfoPath;
  }

  public void setUserInfoPath(String userInfoPath) {
    this.userInfoPath = userInfoPath;
  }
}
