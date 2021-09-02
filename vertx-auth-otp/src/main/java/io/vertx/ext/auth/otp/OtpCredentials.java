/*
 * Copyright (c) 2021 Dmitry Novikov
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.ext.auth.otp;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.totp.TotpAuth;

/**
 * Credentials for {@link HotpAuth} or {@link TotpAuth} authentication providers.
 *
 * @author Dmitry Novikov
 */
@DataObject(generateConverter = true, publicConverter = false)
public class OtpCredentials implements Credentials {

  private String identifier;

  private String code;

  public OtpCredentials(JsonObject jsonObject) {
    OtpCredentialsConverter.fromJson(jsonObject, this);
  }

  public OtpCredentials(String identifier, String code) {
    this.identifier = identifier;
    this.code = code;
  }

  public String getCode() {
    return code;
  }

  public String getIdentifier() {
    return identifier;
  }

  public OtpCredentials setCode(String code) {
    this.code = code;
    return this;
  }

  public OtpCredentials setIdentifier(String identifier) {
    this.identifier = identifier;
    return this;
  }

  @Override
  public <V> void checkValid(V arg) throws CredentialValidationException {
    if (identifier == null || identifier.length() == 0) {
      throw new CredentialValidationException("identifier cannot null or empty");
    }

    if (code == null || code.length() == 0) {
      throw new CredentialValidationException("code cannot null or empty");
    }
  }

  @Override
  public JsonObject toJson() {
    JsonObject result = new JsonObject();
    OtpCredentialsConverter.toJson(this, result);
    return result;
  }
}
