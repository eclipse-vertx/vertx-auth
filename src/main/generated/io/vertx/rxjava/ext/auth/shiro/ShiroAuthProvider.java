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
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;
import io.vertx.rxjava.ext.auth.AuthProvider;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.shiro.ShiroAuthProvider original} non RX-ified interface using Vert.x codegen.
 */

public class ShiroAuthProvider extends AuthProvider {

  final io.vertx.ext.auth.shiro.ShiroAuthProvider delegate;

  public ShiroAuthProvider(io.vertx.ext.auth.shiro.ShiroAuthProvider delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  public static ShiroAuthProvider create(Vertx vertx, ShiroAuthRealmType shiroAuthRealmType, JsonObject config) { 
    ShiroAuthProvider ret= ShiroAuthProvider.newInstance(io.vertx.ext.auth.shiro.ShiroAuthProvider.create((io.vertx.core.Vertx) vertx.getDelegate(), shiroAuthRealmType, config));
    return ret;
  }


  public static ShiroAuthProvider newInstance(io.vertx.ext.auth.shiro.ShiroAuthProvider arg) {
    return new ShiroAuthProvider(arg);
  }
}
