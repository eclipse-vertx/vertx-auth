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
package io.vertx.ext.auth.sql;

import io.vertx.codegen.annotations.DataObject;
import io.vertx.codegen.annotations.Fluent;
import io.vertx.core.json.JsonObject;

/**
 * Options configuring JDBC authentication.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 */
@DataObject(generateConverter = true)
public class SQLAuthenticationOptions {

  /**
   * The default query to be used for authentication
   */
  private final static String DEFAULT_AUTHENTICATE_QUERY = "SELECT PASSWORD FROM USER WHERE USERNAME = ?";

  private String authenticationQuery;

  public SQLAuthenticationOptions() {
    this.authenticationQuery = DEFAULT_AUTHENTICATE_QUERY;
  }

  public SQLAuthenticationOptions(JsonObject json) {
    this();
    SQLAuthenticationOptionsConverter.fromJson(json, this);
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
  public SQLAuthenticationOptions setAuthenticationQuery(String authenticationQuery) {
    this.authenticationQuery = authenticationQuery;
    return this;
  }

}
