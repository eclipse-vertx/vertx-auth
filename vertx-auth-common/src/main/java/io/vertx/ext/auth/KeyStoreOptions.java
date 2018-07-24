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
import io.vertx.core.json.JsonObject;

/**
 * Options describing how an JWT KeyStore should behave.
 *
 * @deprecated Keystores are very opinionated and do not properly represent a correct key, please use PEM files or JWKs
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
@Deprecated
@DataObject(generateConverter = true)
public class KeyStoreOptions {

  // Defaults
  private static final String TYPE = "jceks";

  private String type;
  private String path;
  private String password;

  /**
   * Default constructor
   */
  public KeyStoreOptions() {
    init();
  }

  /**
   * Copy constructor
   *
   * @param other the options to copy
   */
  public KeyStoreOptions(KeyStoreOptions other) {
    type = other.getType();
    path = other.getPath();
    password = other.getPassword();
  }

  private void init() {
    type = TYPE;
  }

  /**
   * Constructor to create an options from JSON
   *
   * @param json the JSON
   */
  public KeyStoreOptions(JsonObject json) {
    init();
    KeyStoreOptionsConverter.fromJson(json, this);
  }

  public String getType() {
    return type;
  }

  public KeyStoreOptions setType(String type) {
    this.type = type;
    return this;
  }

  public String getPath() {
    return path;
  }

  public KeyStoreOptions setPath(String path) {
    this.path = path;
    return this;
  }

  public String getPassword() {
    return password;
  }

  public KeyStoreOptions setPassword(String password) {
    this.password = password;
    return this;
  }
}
