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

package io.vertx.ext.auth.otp.totp;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Options configuring TOTP authentication.
 *
 * @author Dmitry Novikov
 */
@DataObject
@JsonGen(publicConverter = false)
public class TotpAuthOptions {

  private int passwordLength = 6;

  private int authAttemptsLimit;

  private long period = 30;

  public TotpAuthOptions(JsonObject jsonObject) {
    TotpAuthOptionsConverter.fromJson(jsonObject, this);
  }

  public TotpAuthOptions() {
  }

  public TotpAuthOptions(int passwordLength, int authAttemptsLimit, long period) {
    setPasswordLength(passwordLength);
    setAuthAttemptsLimit(authAttemptsLimit);
    setPeriod(period);
  }

  public int getPasswordLength() {
    return passwordLength;
  }

  public int getAuthAttemptsLimit() {
    return authAttemptsLimit;
  }

  public long getPeriod() {
    return period;
  }

  public TotpAuthOptions setPasswordLength(int passwordLength) {
    if (passwordLength < 6 || passwordLength > 8) {
      throw new IllegalArgumentException("password length must be between 6 and 8 digits");
    }
    this.passwordLength = passwordLength;
    return this;
  }

  public TotpAuthOptions setAuthAttemptsLimit(int authAttemptsLimit) {
    if (authAttemptsLimit < 0) {
      throw new IllegalArgumentException("Auth attempts limit must above 0");
    }
    this.authAttemptsLimit = authAttemptsLimit;
    return this;
  }

  public TotpAuthOptions setPeriod(long period) {
    if (period < 0) {
      throw new IllegalArgumentException("Period must above 0");
    }
    this.period = period;
    return this;
  }

  @GenIgnore
  public boolean isUsingAttemptsLimit() {
    return authAttemptsLimit > 0;
  }
}
