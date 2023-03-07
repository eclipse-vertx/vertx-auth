/*
 * Copyright (c) 2021 Paulo Lopes
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
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.core.json.JsonObject;

/**
 * Authenticator of specific user.
 *
 * @author Paulo Lopes
 */
@DataObject(generateConverter = true)
public class Authenticator {

  private String identifier;
  private String key;
  private String algorithm;

  private long counter;
  private long period;
  private Integer authAttempts;

  boolean registration;

  public Authenticator(boolean registration) {
    this.registration = registration;
  }

  public Authenticator() {
  }

  public Authenticator(JsonObject json) {
    AuthenticatorConverter.fromJson(json, this);
  }

  public String getIdentifier() {
    return identifier;
  }

  public Authenticator setIdentifier(String identifier) {
    this.identifier = identifier;
    return this;
  }

  public String getKey() {
    return key;
  }

  public Authenticator setKey(String key) {
    this.key = key;
    return this;
  }

  public String getAlgorithm() {
    return algorithm;
  }

  public Authenticator setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public long getCounter() {
    return counter;
  }

  public Authenticator setCounter(long counter) {
    this.counter = counter;
    return this;
  }

  public long getPeriod() {
    return period;
  }

  public Authenticator setPeriod(long period) {
    this.period = period;
    return this;
  }

  public Integer getAuthAttempts() {
    return authAttempts;
  }

  public Authenticator setAuthAttempts(Integer authAttempts) {
    this.authAttempts = authAttempts;
    return this;
  }

  @GenIgnore
  public boolean isRegistration() {
    return registration;
  }

  @GenIgnore
  public Authenticator registered() {
    registration = false;
    return this;
  }

  public JsonObject toJson() {
    final JsonObject json = new JsonObject();
    AuthenticatorConverter.toJson(this, json);
    return json;
  }

  @Override
  public String toString() {
    return toJson().encode();
  }
}
