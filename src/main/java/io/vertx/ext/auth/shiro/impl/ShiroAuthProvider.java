/*
 * Copyright 2014 Red Hat, Inc.
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

package io.vertx.ext.auth.shiro.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.shiro.ShiroAuthRealm;
import io.vertx.ext.auth.spi.AuthProvider;

/**
 *
 * Shiro API is unfortunately inherently synchronous, so we need to execute everything on the worker pool
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthProvider implements AuthProvider {

  private final Vertx vertx;
  private final ShiroAuthRealm realm;

  public ShiroAuthProvider(Vertx vertx, ShiroAuthRealm realm) {
    this.vertx = vertx;
    this.realm = realm;
  }

  @Override
  public void init(JsonObject config) {
    realm.init(config);
  }

  @Override
  public void login(JsonObject credentials, Handler<AsyncResult<Object>> resultHandler) {
    vertx.executeBlocking((Future<Object> fut) -> {
      Object principal = realm.login(credentials);
      fut.complete(principal);
    }, resultHandler);
  }

  @Override
  public void hasRole(Object principal, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      boolean hasRole = realm.hasRole(principal, role);
      fut.complete(hasRole);
    }, resultHandler);
  }

  @Override
  public void hasPermission(Object principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    vertx.executeBlocking((Future<Boolean> fut) -> {
      boolean hasPermission = realm.hasPermission(principal, permission);
      fut.complete(hasPermission);
    }, resultHandler);
  }

}
