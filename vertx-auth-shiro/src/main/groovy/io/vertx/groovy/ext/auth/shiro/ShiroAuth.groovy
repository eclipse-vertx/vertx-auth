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
import io.vertx.core.json.JsonObject
import io.vertx.groovy.ext.auth.User
import io.vertx.groovy.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
import io.vertx.ext.auth.shiro.ShiroAuthOptions
import io.vertx.ext.auth.shiro.ShiroAuthRealmType
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating Apache Shiro based {@link io.vertx.groovy.ext.auth.AuthProvider} instances.
*/
@CompileStatic
public class ShiroAuth extends AuthProvider {
  private final def io.vertx.ext.auth.shiro.ShiroAuth delegate;
  public ShiroAuth(Object delegate) {
    super((io.vertx.ext.auth.shiro.ShiroAuth) delegate);
    this.delegate = (io.vertx.ext.auth.shiro.ShiroAuth) delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Create a Shiro auth provider
   * @param vertx the Vert.x instance
   * @param realmType the Shiro realm type
   * @param config the config
   * @return the auth provider
   */
  public static ShiroAuth create(Vertx vertx, ShiroAuthRealmType realmType, Map<String, Object> config) {
    def ret = InternalHelper.safeCreate(io.vertx.ext.auth.shiro.ShiroAuth.create(vertx != null ? (io.vertx.core.Vertx)vertx.getDelegate() : null, realmType, config != null ? new io.vertx.core.json.JsonObject(config) : null), io.vertx.groovy.ext.auth.shiro.ShiroAuth.class);
    return ret;
  }
  /**
   * Create a Shiro auth provider
   * @param vertx the Vert.x instance
   * @param options the Shiro configuration options (see <a href="../../../../../../../../cheatsheet/ShiroAuthOptions.html">ShiroAuthOptions</a>)
   * @return the auth provider
   */
  public static ShiroAuth create(Vertx vertx, Map<String, Object> options) {
    def ret = InternalHelper.safeCreate(io.vertx.ext.auth.shiro.ShiroAuth.create(vertx != null ? (io.vertx.core.Vertx)vertx.getDelegate() : null, options != null ? new io.vertx.ext.auth.shiro.ShiroAuthOptions(io.vertx.lang.groovy.InternalHelper.toJsonObject(options)) : null), io.vertx.groovy.ext.auth.shiro.ShiroAuth.class);
    return ret;
  }
  /**
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  public ShiroAuth setRolePrefix(String rolePrefix) {
    def ret = InternalHelper.safeCreate(delegate.setRolePrefix(rolePrefix), io.vertx.groovy.ext.auth.shiro.ShiroAuth.class);
    return ret;
  }
}
