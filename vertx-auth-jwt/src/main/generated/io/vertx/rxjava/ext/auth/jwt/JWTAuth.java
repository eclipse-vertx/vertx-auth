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

package io.vertx.rxjava.ext.auth.jwt;

import java.util.Map;
import io.vertx.lang.rxjava.InternalHelper;
import rx.Observable;
import io.vertx.core.net.JksOptions;
import io.vertx.rxjava.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.rxjava.ext.auth.AuthProvider;

/**
 * Factory interface for creating JWT based {@link io.vertx.rxjava.ext.auth.AuthProvider} instances.
 *
 * <p/>
 * NOTE: This class has been automatically generated from the {@link io.vertx.ext.auth.jwt.JWTAuth original} non RX-ified interface using Vert.x codegen.
 */

public class JWTAuth extends AuthProvider {

  final io.vertx.ext.auth.jwt.JWTAuth delegate;

  public JWTAuth(io.vertx.ext.auth.jwt.JWTAuth delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public Object getDelegate() {
    return delegate;
  }

  /**
   * Create a JWT auth provider
   * @param vertx the Vertx instance
   * @param config the config
   * @return the auth provider
   */
  public static JWTAuth create(Vertx vertx, JksOptions config) { 
    JWTAuth ret= JWTAuth.newInstance(io.vertx.ext.auth.jwt.JWTAuth.create((io.vertx.core.Vertx) vertx.getDelegate(), config));
    return ret;
  }

  /**
   * Create a Unsafe JWT auth provider. In this mode tokens will not be signed.
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  public static JWTAuth create(Vertx vertx) { 
    JWTAuth ret= JWTAuth.newInstance(io.vertx.ext.auth.jwt.JWTAuth.create((io.vertx.core.Vertx) vertx.getDelegate()));
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
   * @param options extra options for the generation
   * @return JWT encoded token
   */
  public String generateToken(JsonObject claims, JWTOptions options) { 
    String ret = this.delegate.generateToken(claims, options);
    return ret;
  }


  public static JWTAuth newInstance(io.vertx.ext.auth.jwt.JWTAuth arg) {
    return arg != null ? new JWTAuth(arg) : null;
  }
}
