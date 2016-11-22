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
package io.vertx.ext.auth.htdigest.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;

/**
 * @author Paulo Lopes
 */
public class HtdigestUser implements User {

  private String username;
  private String realm;

  public HtdigestUser(String username, String realm) {
    this.username = username;
    this.realm = realm;
  }

  @Override
  public User isAuthorised(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
    resultHandler.handle(Future.succeededFuture(false));
    return this;
  }

  @Override
  public User clearCache() {
    return this;
  }

  @Override
  public JsonObject principal() {
    return new JsonObject()
      .put("username", username)
      .put("realm", realm);
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
  }
}
