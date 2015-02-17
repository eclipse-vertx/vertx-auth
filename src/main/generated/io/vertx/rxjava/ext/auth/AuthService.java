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

  public static AuthService createEventBusProxy(Vertx vertx, String address) {
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.AuthService.createEventBusProxy((io.vertx.core.Vertx) vertx.getDelegate(), address));
    return ret;
  }

  public void login(JsonObject credentials, Handler<AsyncResult<String>> resultHandler) {
    this.delegate.login(credentials, resultHandler);
  }

  public Observable<String> loginObservable(JsonObject credentials) {
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    login(credentials, resultHandler.toHandler());
    return resultHandler;
  }

  public void loginWithTimeout(JsonObject credentials, long timeout, Handler<AsyncResult<String>> resultHandler) {
    this.delegate.loginWithTimeout(credentials, timeout, resultHandler);
  }

  public Observable<String> loginWithTimeoutObservable(JsonObject credentials, long timeout) {
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    loginWithTimeout(credentials, timeout, resultHandler.toHandler());
    return resultHandler;
  }

  public void logout(String loginID, Handler<AsyncResult<Void>> resultHandler) {
    this.delegate.logout(loginID, resultHandler);
  }

  public Observable<Void> logoutObservable(String loginID) {
    io.vertx.rx.java.ObservableFuture<Void> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    logout(loginID, resultHandler.toHandler());
    return resultHandler;
  }

  public void refreshLoginSession(String loginID, Handler<AsyncResult<Void>> resultHandler) {
    this.delegate.refreshLoginSession(loginID, resultHandler);
  }

  public Observable<Void> refreshLoginSessionObservable(String loginID) {
    io.vertx.rx.java.ObservableFuture<Void> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    refreshLoginSession(loginID, resultHandler.toHandler());
    return resultHandler;
  }

  public void hasRole(String loginID, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRole(loginID, role, resultHandler);
  }

  public Observable<Boolean> hasRoleObservable(String loginID, String role) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRole(loginID, role, resultHandler.toHandler());
    return resultHandler;
  }

  public void hasRoles(String loginID, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRoles(loginID, roles, resultHandler);
  }

  public Observable<Boolean> hasRolesObservable(String loginID, Set<String> roles) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRoles(loginID, roles, resultHandler.toHandler());
    return resultHandler;
  }

  public void hasPermission(String loginID, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermission(loginID, permission, resultHandler);
  }

  public Observable<Boolean> hasPermissionObservable(String loginID, String permission) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermission(loginID, permission, resultHandler.toHandler());
    return resultHandler;
  }

  public void hasPermissions(String loginID, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermissions(loginID, permissions, resultHandler);
  }

  public Observable<Boolean> hasPermissionsObservable(String loginID, Set<String> permissions) {
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermissions(loginID, permissions, resultHandler.toHandler());
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
