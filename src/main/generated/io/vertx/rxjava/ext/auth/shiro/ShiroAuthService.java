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

package io.vertx.rxjava.ext.auth.shiro;

import java.util.Map;
import io.vertx.lang.rxjava.InternalHelper;
import rx.Observable;
import io.vertx.rxjava.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.rxjava.ext.auth.AuthService;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;

/**
 * An Auth service implementation that uses Apache Shiro internally.
 * <p>
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 *
 * NOTE: This class has been automatically generated from the original non RX-ified interface using Vert.x codegen.
 */

public class ShiroAuthService extends AuthService {

  final io.vertx.ext.auth.shiro.ShiroAuthService delegate;

  public ShiroAuthService(io.vertx.ext.auth.shiro.ShiroAuthService delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Create an auth service using the specified auth realm type.
   *
   * @param vertx  the Vert.x intance
   * @param authRealmType  the auth realm type
   * @param config  the config to pass to the provider
   * @return the auth service
   */
  public static AuthService create(Vertx vertx, ShiroAuthRealmType authRealmType, JsonObject config) {
    AuthService ret= AuthService.newInstance(io.vertx.ext.auth.shiro.ShiroAuthService.create((io.vertx.core.Vertx) vertx.getDelegate(), authRealmType, config));
    return ret;
  }


  public static ShiroAuthService newInstance(io.vertx.ext.auth.shiro.ShiroAuthService arg) {
    return new ShiroAuthService(arg);
  }
}
