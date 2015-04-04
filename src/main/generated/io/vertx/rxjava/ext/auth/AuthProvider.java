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
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * This interface is implemented by auth providers which provide the actual auth functionality -
 * e.g. we have a implementation which uses Apache Shiro.
 * <p>
 * If you wish to use the auth service with other providers, implement this interface for your provider.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.AuthProvider original} non RX-ified interface using Vert.x codegen.
 */

public class AuthProvider {

  final io.vertx.ext.auth.AuthProvider delegate;

  public AuthProvider(io.vertx.ext.auth.AuthProvider delegate) {
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Handle the actual login
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials - this can contain anything your provider expects, e.g. password
   * @param resultHandler - this must return a failed result if login fails and it must return a succeeded result if the login succeeds
   */
  public void login(JsonObject principal, JsonObject credentials, Handler<AsyncResult<Void>> resultHandler) { 
    this.delegate.login(principal, credentials, resultHandler);
  }

  /**
   * Handle the actual login
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials - this can contain anything your provider expects, e.g. password
   * @return 
   */
  public Observable<Void> loginObservable(JsonObject principal, JsonObject credentials) { 
    io.vertx.rx.java.ObservableFuture<Void> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    login(principal, credentials, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Handle whether a principal has a role
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param role the role
   * @param resultHandler this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the role, or `false` if they do not have the role.
   */
  public void hasRole(JsonObject principal, String role, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasRole(principal, role, resultHandler);
  }

  /**
   * Handle whether a principal has a role
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param role the role
   * @return 
   */
  public Observable<Boolean> hasRoleObservable(JsonObject principal, String role) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRole(principal, role, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Handle whether a principal has a permission
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param permission the permission
   * @param resultHandler this must return a failure if the check could not be performed - e.g. the principal is not known. Otherwise it must return a succeeded result which contains a boolean `true` if the principal has the permission, or `false` if they do not have the permission.
   */
  public void hasPermission(JsonObject principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasPermission(principal, permission, resultHandler);
  }

  /**
   * Handle whether a principal has a permission
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param permission the permission
   * @return 
   */
  public Observable<Boolean> hasPermissionObservable(JsonObject principal, String permission) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermission(principal, permission, resultHandler.toHandler());
    return resultHandler;
  }


  public static AuthProvider newInstance(io.vertx.ext.auth.AuthProvider arg) {
    return new AuthProvider(arg);
  }
}
