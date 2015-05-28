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
 * Factory interface for creating Apache Shiro based {@link  io.vertx.rxjava.ext.auth.AuthProvider} instances.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.shiro.ShiroAuth original} non RX-ified interface using Vert.x codegen.
 */

public class ShiroAuth extends AuthProvider {

  final io.vertx.ext.auth.shiro.ShiroAuth delegate;

  public ShiroAuth(io.vertx.ext.auth.shiro.ShiroAuth delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  public static ShiroAuth create(Vertx vertx, ShiroAuthRealmType realmType, JsonObject config) { 
    ShiroAuth ret= ShiroAuth.newInstance(io.vertx.ext.auth.shiro.ShiroAuth.create((io.vertx.core.Vertx) vertx.getDelegate(), realmType, config));
    return ret;
  }

  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  public ShiroAuth setRolePrefix(String rolePrefix) { 
    ShiroAuth ret= ShiroAuth.newInstance(this.delegate.setRolePrefix(rolePrefix));
    return ret;
  }


  public static ShiroAuth newInstance(io.vertx.ext.auth.shiro.ShiroAuth arg) {
    return new ShiroAuth(arg);
  }
}
