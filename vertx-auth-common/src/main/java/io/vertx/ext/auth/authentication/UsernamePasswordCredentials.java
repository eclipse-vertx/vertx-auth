/* ******************************************************************************
 * Copyright (c) 2020 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authentication;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;

import java.nio.charset.StandardCharsets;

import static io.vertx.ext.auth.impl.Codec.base64Encode;

/**
 * Credentials used by any {@link AuthenticationProvider} that requires tokens, for example JWT, Oauth2, OpenId Connect
 *
 * @author Paulo Lopes
 */
@DataObject(generateConverter = true, publicConverter = false)
public class UsernamePasswordCredentials implements Credentials {

  private String password;
  private String username;

  protected UsernamePasswordCredentials() {
  }

  public UsernamePasswordCredentials(String username, String password) {
    setUsername(username);
    setPassword(password);
  }

  public UsernamePasswordCredentials(JsonObject jsonObject) {
    UsernamePasswordCredentialsConverter.fromJson(jsonObject, this);
  }

  public String getPassword() {
    return password;
  }

  public String getUsername() {
    return username;
  }

  public UsernamePasswordCredentials setPassword(String password) {
    this.password = password;
    return this;
  }

  public UsernamePasswordCredentials setUsername(String username) {
    this.username = username;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (username == null) {
      throw new CredentialValidationException("username cannot be null");
    }
    // passwords are allowed to be empty
    // for example this is used by basic auth
    if (password == null) {
      throw new CredentialValidationException("password cannot be null");
    }
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    UsernamePasswordCredentialsConverter.toJson(this, result);
    return result;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  @Override
  public UsernamePasswordCredentials applyHttpChallenge(String challenge, HttpMethod method, String uri, Integer nc, String cnonce) throws CredentialValidationException {
    if (challenge != null) {
      int spc = challenge.indexOf(' ');

      if (!"Basic".equalsIgnoreCase(challenge.substring(0, spc))) {
        throw new IllegalArgumentException("Only 'Basic' auth-scheme is supported");
      }
    }
    // validate
    checkValid(null);
    return this;
  }

  @Override
  public String toHttpAuthorization() {
    final StringBuilder sb = new StringBuilder();

    if (username != null) {
      // RFC check
      if (username.indexOf(':') != -1) {
        throw new IllegalArgumentException("Username cannot contain ':'");
      }
      sb.append(username);
    }

    sb.append(':');

    if (password != null) {
      sb.append(password);
    }

    return "Basic " + base64Encode(sb.toString().getBytes(StandardCharsets.UTF_8));
  }

}
