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
@Deprecated
@DataObject
public class KeyStoreOptions extends io.vertx.ext.auth.jose.KeyStoreOptions {

  /**
   * Default constructor
   */
  public KeyStoreOptions() {
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public KeyStoreOptions(KeyStoreOptions other) {
    super(other);
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public KeyStoreOptions(JsonObject json) {
    super(json);
  }

  @Fluent
  public KeyStoreOptions setType(String type) {
    return (KeyStoreOptions) super.setType(type);
  }

  @Fluent
  public KeyStoreOptions setProvider(String provider) {
    return (KeyStoreOptions) super.setProvider(provider);
  }

  @Fluent
  public KeyStoreOptions setPassword(String password) {
    return (KeyStoreOptions) super.setPassword(password);
  }

  @Fluent
  public KeyStoreOptions setPath(String path) {
    return (KeyStoreOptions) super.setPath(path);
  }

  @Fluent
  @Deprecated
  public KeyStoreOptions setValue(Buffer value) {
    return (KeyStoreOptions) super.setValue(value);
  }

  @Fluent
  public KeyStoreOptions setPasswordProtection(Map<String, String> passwordProtection) {
    return (KeyStoreOptions) super.setPasswordProtection(passwordProtection);
  }

  public KeyStoreOptions putPasswordProtection(String alias, String password) {
    return (KeyStoreOptions) super.putPasswordProtection(alias, password);
  }
}
