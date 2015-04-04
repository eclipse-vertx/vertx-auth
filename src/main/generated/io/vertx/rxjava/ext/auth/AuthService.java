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
 * Vert.x authentication and authorisation service.
 * <p>
 * Handles authentication and role/permission based authorisation.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.AuthService original} non RX-ified interface using Vert.x codegen.
 */

public class AuthService {

  final io.vertx.ext.auth.AuthService delegate;

  public AuthService(io.vertx.ext.auth.AuthService delegate) {
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Create an auth service instance using the specified auth provider class name.
   * @param vertx the Vert.x instance
   * @param className the fully qualified class name of the auth provider implementation class
   * @return the auth service
   */
  public static AuthService createFromClassName(Vertx vertx, String className) { 
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.AuthService.createFromClassName((io.vertx.core.Vertx) vertx.getDelegate(), className));
    return ret;
  }

  /**
   * Create a proxy to an auth service that is deployed somwehere on the event bus.
   * @param vertx the vert.x instance
   * @param address the address on the event bus where the auth service is listening
   * @return the proxy
   */
  public static AuthService createEventBusProxy(Vertx vertx, String address) { 
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.AuthService.createEventBusProxy((io.vertx.core.Vertx) vertx.getDelegate(), address));
    return ret;
  }

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The default login ID timeout will be used.
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials - e.g. password
   * @param resultHandler will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful.
   * @return 
   */
  public AuthService login(JsonObject principal, JsonObject credentials, Handler<AsyncResult<String>> resultHandler) { 
    this.delegate.login(principal, credentials, resultHandler);
    return this;
  }

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The default login ID timeout will be used.
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials - e.g. password
   * @return 
   */
  public Observable<String> loginObservable(JsonObject principal, JsonObject credentials) { 
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    login(principal, credentials, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The specified login ID timeout will be used.
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials
   * @param timeout the login timeout to use, in ms
   * @param resultHandler will be passed a failed result if login failed or will be passed a succeeded result containing the login ID (a string) if login was successful.
   * @return 
   */
  public AuthService loginWithTimeout(JsonObject principal, JsonObject credentials, long timeout, Handler<AsyncResult<String>> resultHandler) { 
    this.delegate.loginWithTimeout(principal, credentials, timeout, resultHandler);
    return this;
  }

  /**
   * Authenticate (login) using the specified credentials. The contents of the credentials depend on what the auth
   * provider is expecting. The specified login ID timeout will be used.
   * @param principal represents the unique id (e.g. username) of the user being logged in
   * @param credentials the credentials
   * @param timeout the login timeout to use, in ms
   * @return 
   */
  public Observable<String> loginWithTimeoutObservable(JsonObject principal, JsonObject credentials, long timeout) { 
    io.vertx.rx.java.ObservableFuture<String> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    loginWithTimeout(principal, credentials, timeout, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Logout the user
   * @param loginID the login ID as provided by {@link #login}.
   * @param resultHandler will be called with success or failure
   * @return 
   */
  public AuthService logout(String loginID, Handler<AsyncResult<Void>> resultHandler) { 
    this.delegate.logout(loginID, resultHandler);
    return this;
  }

  /**
   * Logout the user
   * @param loginID the login ID as provided by {@link #login}.
   * @return 
   */
  public Observable<Void> logoutObservable(String loginID) { 
    io.vertx.rx.java.ObservableFuture<Void> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    logout(loginID, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Refresh an existing login ID so it doesn't expire
   * @param loginID the login ID as provided by {@link #login}.
   * @param resultHandler will be called with success or failure
   * @return 
   */
  public AuthService refreshLoginSession(String loginID, Handler<AsyncResult<Void>> resultHandler) { 
    this.delegate.refreshLoginSession(loginID, resultHandler);
    return this;
  }

  /**
   * Refresh an existing login ID so it doesn't expire
   * @param loginID the login ID as provided by {@link #login}.
   * @return 
   */
  public Observable<Void> refreshLoginSessionObservable(String loginID) { 
    io.vertx.rx.java.ObservableFuture<Void> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    refreshLoginSession(loginID, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have the specified role?
   * @param loginID the login ID as provided by {@link #login}.
   * @param role the role
   * @param resultHandler will be called with the result - true if has role, false if not
   * @return 
   */
  public AuthService hasRole(String loginID, String role, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasRole(loginID, role, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified role?
   * @param loginID the login ID as provided by {@link #login}.
   * @param role the role
   * @return 
   */
  public Observable<Boolean> hasRoleObservable(String loginID, String role) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRole(loginID, role, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have the specified roles?
   * @param loginID the login ID as provided by {@link #login}.
   * @param roles the set of roles
   * @param resultHandler will be called with the result - true if has roles, false if not
   * @return 
   */
  public AuthService hasRoles(String loginID, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasRoles(loginID, roles, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified roles?
   * @param loginID the login ID as provided by {@link #login}.
   * @param roles the set of roles
   * @return 
   */
  public Observable<Boolean> hasRolesObservable(String loginID, Set<String> roles) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRoles(loginID, roles, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have the specified permission?
   * @param loginID the login ID as provided by {@link #login}.
   * @param permission the permission
   * @param resultHandler will be called with the result - true if has permission, false if not
   * @return 
   */
  public AuthService hasPermission(String loginID, String permission, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasPermission(loginID, permission, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified permission?
   * @param loginID the login ID as provided by {@link #login}.
   * @param permission the permission
   * @return 
   */
  public Observable<Boolean> hasPermissionObservable(String loginID, String permission) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermission(loginID, permission, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have the specified permissions?
   * @param loginID the login ID as provided by {@link #login}.
   * @param permissions the set of permissions
   * @param resultHandler will be called with the result - true if has permissions, false if not
   * @return 
   */
  public AuthService hasPermissions(String loginID, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasPermissions(loginID, permissions, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified permissions?
   * @param loginID the login ID as provided by {@link #login}.
   * @param permissions the set of permissions
   * @return 
   */
  public Observable<Boolean> hasPermissionsObservable(String loginID, Set<String> permissions) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermissions(loginID, permissions, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Set the reaper period - how often to check for expired logins, in ms.
   * @param reaperPeriod the reaper period, in ms
   * @return 
   */
  public AuthService setReaperPeriod(long reaperPeriod) { 
    this.delegate.setReaperPeriod(reaperPeriod);
    return this;
  }

  /**
   * Start the service
   */
  public void start() { 
    this.delegate.start();
  }

  /**
   * Stop the service
   */
  public void stop() { 
    this.delegate.stop();
  }


  public static AuthService newInstance(io.vertx.ext.auth.AuthService arg) {
    return new AuthService(arg);
  }
}
