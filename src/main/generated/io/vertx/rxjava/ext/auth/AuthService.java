/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.rxjava.ext.auth;

import java.util.Map;
import io.vertx.lang.rxjava.InternalHelper;
import rx.Observable;
import io.vertx.rxjava.core.Vertx;
import java.util.Set;
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 *
 * NOTE: This class has been automatically generated from the original non RX-ified interface using Vert.x codegen.
 */

public class AuthService {

  final io.vertx.ext.auth.AuthService delegate;

  public AuthService(io.vertx.ext.auth.AuthService delegate) {
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  public static AuthService create(Vertx vertx, JsonObject config) {
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.AuthService.create((io.vertx.core.Vertx) vertx.getDelegate(), config));
    return ret;
  }

  public static AuthService createEventBusProxy(Vertx vertx, String address) {
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.AuthService.createEventBusProxy((io.vertx.core.Vertx) vertx.getDelegate(), address));
    return ret;
  }

  public void login(JsonObject credentials, Handler<AsyncResult<String>> resultHandler) {
    this.delegate.login(credentials, resultHandler);
  }

  public Observable<String> loginObservable(JsonObject credentials) {
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    login(credentials, resultHandler.asHandler());
    return resultHandler;
  }

  public void hasRole(String principal, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRole(principal, role, resultHandler);
  }

  public Observable<Boolean> hasRoleObservable(String principal, String role) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRole(principal, role, resultHandler.asHandler());
    return resultHandler;
  }

  public void hasRoles(String principal, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRoles(principal, roles, resultHandler);
  }

  public Observable<Boolean> hasRolesObservable(String principal, Set<String> roles) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRoles(principal, roles, resultHandler.asHandler());
    return resultHandler;
  }

  public void hasPermission(String principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermission(principal, permission, resultHandler);
  }

  public Observable<Boolean> hasPermissionObservable(String principal, String permission) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermission(principal, permission, resultHandler.asHandler());
    return resultHandler;
  }

  public void hasPermissions(String principal, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermissions(principal, permissions, resultHandler);
  }

  public Observable<Boolean> hasPermissionsObservable(String principal, Set<String> permissions) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermissions(principal, permissions, resultHandler.asHandler());
    return resultHandler;
  }

  public void start() {
    this.delegate.start();
  }

  public void stop() {
    this.delegate.stop();
  }


  public static AuthService newInstance(io.vertx.ext.auth.AuthService arg) {
    return new AuthService(arg);
  }
}
