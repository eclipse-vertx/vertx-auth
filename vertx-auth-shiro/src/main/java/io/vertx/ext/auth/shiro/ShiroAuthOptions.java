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
package io.vertx.ext.auth.shiro;


import io.vertx.codegen.annotations.DataObject;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;

/**
 * Shiro auth configuration options, see Vert.x Auth Shiro component and/or Apache Shiro project.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class ShiroAuthOptions implements io.vertx.ext.auth.AuthOptions {

  public static final ShiroAuthRealmType DEFAULT_TYPE = ShiroAuthRealmType.PROPERTIES;

  private ShiroAuthRealmType type;
  private JsonObject config;

  public ShiroAuthOptions() {
    type = DEFAULT_TYPE;
  }

  public ShiroAuthOptions(ShiroAuthOptions that) {
    type = that.type;
    config = that.config != null ? that.config.copy() : null;
  }

  public ShiroAuthOptions(JsonObject json) {
    this();
    ShiroAuthOptionsConverter.fromJson(json, this);
  }

  /**
   * @return the Shiro realm type
   */
  public ShiroAuthRealmType getType() {
    return type;
  }

  /**
   * Set the Shiro auth options type.
   *
   * @param type the type
   * @return a reference to this, so the API can be used fluently
   */
  public ShiroAuthOptions setType(ShiroAuthRealmType type) {
    this.type = type;
    return this;
  }

  /**
   * @return the Shiro auth config
   */
  public JsonObject getConfig() {
    return config;
  }

  /**
   * Set the Shiro auth config.
   *
   * @param config the config
   * @return a reference to this, so the API can be used fluently
   */
  public ShiroAuthOptions setConfig(JsonObject config) {
    this.config = config;
    return this;
  }

  @Override
  public ShiroAuthOptions clone() {
    return new ShiroAuthOptions(this);
  }

  @Override
  public AuthProvider createProvider(Vertx vertx) {
    return ShiroAuth.create(vertx, this);
  }
}