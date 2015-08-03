/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.jwt;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl;

/**
 * Factory interface for creating JWT based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface JWTAuth extends AuthProvider {

  /**
   * Create a JWT auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static JWTAuth create(Vertx vertx, JksOptions config) {
    return new JWTAuthProviderImpl(vertx, config);
  }

  /**
   * Create a Unsafe JWT auth provider. In this mode tokens will not be signed.
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static JWTAuth create(Vertx vertx) {
    return new JWTAuthProviderImpl(vertx, null);
  }

  /**
   * Sets the key name in the json token where permission claims will be listed.
   *
   * @param name the key name
   * @return self
   */
  @Fluent
  JWTAuth setPermissionsClaimKey(String name);

  /**
   * Generate a new JWT token.
   *
   * @param claims Json with user defined claims for a list of official claims
   *               @see <a href="http://www.iana.org/assignments/jwt/jwt.xhtml">www.iana.org/assignments/jwt/jwt.xhtml</a>
   * @param options extra options for the generation
   *
   * @return JWT encoded token
   */
  String generateToken(JsonObject claims, JWTOptions options);
}