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
package io.vertx.ext.auth;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

/**
 * Options describing how an JWT KeyStore should behave.
 * This is an extended version core's {@link io.vertx.core.net.KeyStoreOptions}.
 * <p>
 * This extension sets the default type to the runtime keystore type (for compatibility, reasons)
 * plus it allows the configuration of password per key using {@link #setPasswordProtection(Map)}.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class KeyStoreOptions {

  // Defaults
  private static final String DEFAULT_TYPE = KeyStore.getDefaultType();

  private String type;
  private String provider;
  private String password;
  private String path;
  @Deprecated
  private Buffer value;
  private Map<String, String> passwordProtection;

  /**
   * Default constructor
   */
  public KeyStoreOptions() {
    type = DEFAULT_TYPE;
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public KeyStoreOptions(KeyStoreOptions other) {
    type = other.getType();
    if (type == null) {
      type = DEFAULT_TYPE;
    }
    password = other.getPassword();
    path = other.getPath();
    value = other.getValue();
    passwordProtection = other.getPasswordProtection();
    provider = other.getProvider();
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public KeyStoreOptions(JsonObject json) {
    KeyStoreOptionsConverter.fromJson(json, this);
  }

  @Fluent
  public KeyStoreOptions setType(String type) {
    this.type = type;
    return this;
  }

  @Fluent
  public KeyStoreOptions setProvider(String provider) {
    this.provider = provider;
    return this;
  }

  @Fluent
  public KeyStoreOptions setPassword(String password) {
    this.password = password;
    return this;
  }

  @Fluent
  public KeyStoreOptions setPath(String path) {
    this.path = path;
    return this;
  }

  @Fluent
  @Deprecated
  public KeyStoreOptions setValue(Buffer value) {
    this.value = value;
    return this;
  }

  @Fluent
  public KeyStoreOptions setPasswordProtection(Map<String, String> passwordProtection) {
    this.passwordProtection = passwordProtection;
    return this;
  }

  public String getType() {
    return type;
  }

  public String getProvider() {
    return provider;
  }

  public String getPassword() {
    return password;
  }

  public String getPath() {
    return path;
  }

  @Deprecated
  public Buffer getValue() {
    return value;
  }

  public Map<String, String> getPasswordProtection() {
    return passwordProtection;
  }

  public KeyStoreOptions putPasswordProtection(String alias, String password) {
    if (passwordProtection == null) {
      passwordProtection = new HashMap<>();
    }

    this.passwordProtection.put(alias, password);
    return this;
  }
}
