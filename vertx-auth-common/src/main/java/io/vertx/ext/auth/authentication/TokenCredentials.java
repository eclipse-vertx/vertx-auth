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
import io.vertx.core.json.JsonObject;

/**
 * Credentials used by any {@link AuthenticationProvider} that requires Tokens, such as OAuth2 or JWT
 * to perform its authentication
 *
 * @author Paulo Lopes
 *
 */
@DataObject(generateConverter = true, publicConverter = false)
public class TokenCredentials implements Credentials {

  private String token;

  protected TokenCredentials() {}

  public TokenCredentials(String token) {
    this.token = token;
  }

  public TokenCredentials(JsonObject jsonObject) {
    TokenCredentialsConverter.fromJson(jsonObject, this);
  }

  public String getToken() {
    return token;
  }

  public TokenCredentials setToken(String token) {
    this.token = token;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (token == null || token.length() == 0) {
      throw new CredentialValidationException("token cannot be null or empty");
    }
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    TokenCredentialsConverter.toJson(this, result);
    return result;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }

  @Override
  public String toHttpHeader() {
    return "Bearer " + token;
  }
}
