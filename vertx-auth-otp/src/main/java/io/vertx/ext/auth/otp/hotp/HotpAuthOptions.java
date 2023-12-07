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

package io.vertx.ext.auth.otp.hotp;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Options configuring HOTP authentication.
 *
 * @author Dmitry Novikov
 */
@DataObject
@JsonGen(publicConverter = false)
public class HotpAuthOptions {

  private int passwordLength = 6;

  private int authAttemptsLimit;

  private int lookAheadWindow;

  private long counter;

  public HotpAuthOptions(JsonObject jsonObject) {
    HotpAuthOptionsConverter.fromJson(jsonObject, this);
  }

  public HotpAuthOptions() {
  }

  public HotpAuthOptions(int passwordLength, int authAttemptsLimit, int lookAheadWindow) {
    setPasswordLength(passwordLength);
    setAuthAttemptsLimit(authAttemptsLimit);
    setLookAheadWindow(lookAheadWindow);
  }

  public int getPasswordLength() {
    return passwordLength;
  }

  public int getAuthAttemptsLimit() {
    return authAttemptsLimit;
  }

  public int getLookAheadWindow() {
    return lookAheadWindow;
  }

  public long getCounter() {
    return counter;
  }

  public HotpAuthOptions setPasswordLength(int passwordLength) {
    if (passwordLength < 6 || passwordLength > 8) {
      throw new IllegalArgumentException("password length must be between 6 and 8 digits");
    }
    this.passwordLength = passwordLength;
    return this;
  }

  public HotpAuthOptions setAuthAttemptsLimit(int authAttemptsLimit) {
    if (authAttemptsLimit < 0) {
      throw new IllegalArgumentException("Auth attempts limit must above 0");
    }
    this.authAttemptsLimit = authAttemptsLimit;
    return this;
  }

  public HotpAuthOptions setLookAheadWindow(int lookAheadWindow) {
    if (lookAheadWindow < 0) {
      throw new IllegalArgumentException("look ahead window must above 0");
    }
    this.lookAheadWindow = lookAheadWindow;
    return this;
  }

  public HotpAuthOptions setCounter(long counter) {
    if (counter < 0) {
      throw new IllegalArgumentException("Authenticator initial counter must above 0");
    }
    this.counter = counter;
    return this;
  }

  @GenIgnore
  public boolean isUsingAttemptsLimit() {
    return authAttemptsLimit > 0;
  }

  @GenIgnore
  public boolean isUsingResynchronization() {
    return lookAheadWindow > 0;
  }
}
