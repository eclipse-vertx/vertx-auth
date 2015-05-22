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
import java.util.Set;
import io.vertx.core.json.JsonObject;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * Represents an authenticate User and contains operations to authorise the user, using a role/permission
 * based model.
 * <p>
 * Please consult the documentation for a detailed explanation.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.User original} non RX-ified interface using Vert.x codegen.
 */

public class User {

  final io.vertx.ext.auth.User delegate;

  public User(io.vertx.ext.auth.User delegate) {
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Does the user have the specified role?
   * @param role the role
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the role or `false` otherwise.
   * @return the User to enable fluent use
   */
  public User hasRole(String role, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasRole(role, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified role?
   * @param role the role
   * @return 
   */
  public Observable<Boolean> hasRoleObservable(String role) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRole(role, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have the specified permission?
   * @param permission the permission
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have the permission or `false` otherwise.
   * @return the User to enable fluent use
   */
  public User hasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasPermission(permission, resultHandler);
    return this;
  }

  /**
   * Does the user have the specified permission?
   * @param permission the permission
   * @return 
   */
  public Observable<Boolean> hasPermissionObservable(String permission) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermission(permission, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have all the specified roles?
   * @param roles the set of roles
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have all the roles or `false` otherwise.
   * @return the User to enable fluent use
   */
  public User hasRoles(Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasRoles(roles, resultHandler);
    return this;
  }

  /**
   * Does the user have all the specified roles?
   * @param roles the set of roles
   * @return 
   */
  public Observable<Boolean> hasRolesObservable(Set<String> roles) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasRoles(roles, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * Does the user have all the specified permissions?
   * @param permissions the set of permissions
   * @param resultHandler handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value `true` if the they have all the permissions or `false` otherwise.
   * @return the User to enable fluent use
   */
  public User hasPermissions(Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) { 
    this.delegate.hasPermissions(permissions, resultHandler);
    return this;
  }

  /**
   * Does the user have all the specified permissions?
   * @param permissions the set of permissions
   * @return 
   */
  public Observable<Boolean> hasPermissionsObservable(Set<String> permissions) { 
    io.vertx.rx.java.ObservableFuture<Boolean> resultHandler = io.vertx.rx.java.RxHelper.observableFuture();
    hasPermissions(permissions, resultHandler.toHandler());
    return resultHandler;
  }

  /**
   * The User object will cache any roles or permissions that it knows it has to avoid hitting the
   * underlying auth provider each time.  Use this method if you want to clear this cache.
   * @return the User to enable fluent use
   */
  public User clearCache() { 
    this.delegate.clearCache();
    return this;
  }

  /**
   * Get the underlying principal for the User. What this actually returns depends on the implementation.
   * For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username", "tim"
   *   }
   * </pre>
   * @return 
   */
  public JsonObject principal() { 
    JsonObject ret = this.delegate.principal();
    return ret;
  }

  /**
   * Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
   * after it has been deserialized.
   * @param authProvider the AuthProvider - this must be the same type of AuthProvider that originally created the User
   */
  public void setAuthProvider(AuthProvider authProvider) { 
    this.delegate.setAuthProvider((io.vertx.ext.auth.AuthProvider) authProvider.getDelegate());
  }


  public static User newInstance(io.vertx.ext.auth.User arg) {
    return new User(arg);
  }
}
