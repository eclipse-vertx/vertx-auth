/********************************************************************************
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
package io.vertx.ext.auth.jwt;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;

/**
 * Credentials specific to the {@link JWTAuth} provider
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 *
 */
@DataObject(generateConverter = true, publicConverter = false)
public class JWTCredentials implements Credentials {

  private String jwt;

  public JWTCredentials() {
  }

  public JWTCredentials(JsonObject jsonObject) {
    JWTCredentialsConverter.fromJson(jsonObject, this);
  }

  public String getJwt() {
    return jwt;
  }

  public JWTCredentials setJwt(String jwt) {
    this.jwt = jwt;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (jwt == null || jwt.length() < 2) {
      // a token has at least 2 segments splitted by a dot
      throw new CredentialValidationException("jwt cannot be null or empty");
    }
  }

  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    JWTCredentialsConverter.toJson(this,
    result); return result;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
