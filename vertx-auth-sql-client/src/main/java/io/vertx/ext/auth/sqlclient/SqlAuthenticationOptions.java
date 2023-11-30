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
package io.vertx.ext.auth.sqlclient;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.json.annotations.JsonGen;
import io.vertx.core.json.JsonObject;

/**
 * Options configuring JDBC authentication.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject
@JsonGen(publicConverter = false)
public class SqlAuthenticationOptions {

  /**
   * The default query to be used for authentication
   */
  private final static String DEFAULT_AUTHENTICATE_QUERY = "SELECT password FROM users WHERE username = ?";

  private String authenticationQuery;

  public SqlAuthenticationOptions() {
    this.authenticationQuery = DEFAULT_AUTHENTICATE_QUERY;
  }

  public SqlAuthenticationOptions(JsonObject json) {
    this();
    SqlAuthenticationOptionsConverter.fromJson(json, this);
  }

  public String getAuthenticationQuery() {
    return authenticationQuery;
  }

  /**
   * Set the authentication query to use. Use this if you want to override the
   * default authentication query.
   *
   * @param authenticationQuery the authentication query
   * @return a reference to this, so the API can be used fluently
   */
  @Fluent
  public SqlAuthenticationOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
    return this;
  }

  public JsonObject toJson() {
    JsonObject json = new JsonObject();
    SqlAuthenticationOptionsConverter.toJson(this, json);
    return json;
  }
}
