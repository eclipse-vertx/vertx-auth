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

package io.vertx.groovy.ext.auth.shiro;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.groovy.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.shiro.ShiroAuthRealmType
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating Apache Shiro based {@link io.vertx.groovy.ext.auth.AuthProvider} instances.
*/
@CompileStatic
public class ShiroAuth {
  final def io.vertx.ext.auth.shiro.ShiroAuth delegate;
  public ShiroAuth(io.vertx.ext.auth.shiro.ShiroAuth delegate) {
    this.delegate = delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  public static AuthProvider create(Vertx vertx, ShiroAuthRealmType realmType, Map<String, Object> config) {
    def ret= new io.vertx.groovy.ext.auth.AuthProvider(io.vertx.ext.auth.shiro.ShiroAuth.create((io.vertx.core.Vertx)vertx.getDelegate(), realmType, config != null ? new io.vertx.core.json.JsonObject(config) : null));
    return ret;
  }
}
