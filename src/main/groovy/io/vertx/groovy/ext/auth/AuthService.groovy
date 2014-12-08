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

package io.vertx.groovy.ext.auth;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.groovy.core.Vertx
import java.util.Set
import io.vertx.core.json.JsonObject
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@CompileStatic
public class AuthService {
  final def io.vertx.ext.auth.AuthService delegate;
  public AuthService(io.vertx.ext.auth.AuthService delegate) {
    this.delegate = delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  public static AuthService create(Vertx vertx, Map<String, Object> config) {
    def ret= AuthService.FACTORY.apply(io.vertx.ext.auth.AuthService.create((io.vertx.core.Vertx)vertx.getDelegate(), config != null ? new io.vertx.core.json.JsonObject(config) : null));
    return ret;
  }
  public static AuthService createEventBusProxy(Vertx vertx, String address) {
    def ret= AuthService.FACTORY.apply(io.vertx.ext.auth.AuthService.createEventBusProxy((io.vertx.core.Vertx)vertx.getDelegate(), address));
    return ret;
  }
  public void login(Map<String, Object> credentials, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.login(credentials != null ? new io.vertx.core.json.JsonObject(credentials) : null, resultHandler);
  }
  public void hasRole(String principal, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRole(principal, role, resultHandler);
  }
  public void hasRoles(String principal, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasRoles(principal, roles, resultHandler);
  }
  public void hasPermission(String principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermission(principal, permission, resultHandler);
  }
  public void hasPermissions(String principal, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler) {
    this.delegate.hasPermissions(principal, permissions, resultHandler);
  }
  public void start() {
    this.delegate.start();
  }
  public void stop() {
    this.delegate.stop();
  }

  static final java.util.function.Function<io.vertx.ext.auth.AuthService, AuthService> FACTORY = io.vertx.lang.groovy.Factories.createFactory() {
    io.vertx.ext.auth.AuthService arg -> new AuthService(arg);
  };
}
