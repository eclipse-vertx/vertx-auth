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

package io.vertx.groovy.ext.auth.jwt;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.core.net.JksOptions
import io.vertx.groovy.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.jwt.JWTOptions
import io.vertx.groovy.ext.auth.AuthProvider
/**
 * Factory interface for creating JWT based {@link io.vertx.groovy.ext.auth.AuthProvider} instances.
*/
@CompileStatic
public class JWTAuth extends AuthProvider {
  private final def io.vertx.ext.auth.jwt.JWTAuth delegate;
  public JWTAuth(Object delegate) {
    super((io.vertx.ext.auth.jwt.JWTAuth) delegate);
    this.delegate = (io.vertx.ext.auth.jwt.JWTAuth) delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
  /**
   * Create a JWT auth provider
   * @param vertx the Vertx instance
   * @param config the config (see <a href="../../../../../../../../cheatsheet/JksOptions.html">JksOptions</a>)
   * @return the auth provider
   */
  public static JWTAuth create(Vertx vertx, Map<String, Object> config) {
    def ret= InternalHelper.safeCreate(io.vertx.ext.auth.jwt.JWTAuth.create((io.vertx.core.Vertx)vertx.getDelegate(), config != null ? new io.vertx.core.net.JksOptions(new io.vertx.core.json.JsonObject(config)) : null), io.vertx.groovy.ext.auth.jwt.JWTAuth.class);
    return ret;
  }
  /**
   * Create a Unsafe JWT auth provider. In this mode tokens will not be signed.
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  public static JWTAuth create(Vertx vertx) {
    def ret= InternalHelper.safeCreate(io.vertx.ext.auth.jwt.JWTAuth.create((io.vertx.core.Vertx)vertx.getDelegate()), io.vertx.groovy.ext.auth.jwt.JWTAuth.class);
    return ret;
  }
  /**
   * Sets the key name in the json token where permission claims will be listed.
   * @param name the key name
   * @return self
   */
  public JWTAuth setPermissionsClaimKey(String name) {
    this.delegate.setPermissionsClaimKey(name);
    return this;
  }
  /**
   * Generate a new JWT token.
   * @param claims Json with user defined claims for a list of official claims
   * @param options extra options for the generation (see <a href="../../../../../../../../cheatsheet/JWTOptions.html">JWTOptions</a>)
   * @return JWT encoded token
   */
  public String generateToken(Map<String, Object> claims, Map<String, Object> options) {
    def ret = this.delegate.generateToken(claims != null ? new io.vertx.core.json.JsonObject(claims) : null, options != null ? new io.vertx.ext.auth.jwt.JWTOptions(new io.vertx.core.json.JsonObject(options)) : null);
    return ret;
  }
}
