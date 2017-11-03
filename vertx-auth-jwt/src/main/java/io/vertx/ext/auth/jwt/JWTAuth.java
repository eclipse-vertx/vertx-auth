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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.jwt.impl.JWTAuthProviderImpl;
import io.vertx.ext.jwt.JWTOptions;

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
  @Deprecated
  @GenIgnore
  static JWTAuth create(Vertx vertx, JsonObject config) {
    return create(vertx, new JWTAuthOptions(config));
  }

  /**
   * Create a JWT auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static JWTAuth create(Vertx vertx, JWTAuthOptions config) {
    return new JWTAuthProviderImpl(vertx, config);
  }

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

  /**
   * Generate a new JWT token.
   *
   * @param claims Json with user defined claims for a list of official claims
   *               @see <a href="http://www.iana.org/assignments/jwt/jwt.xhtml">www.iana.org/assignments/jwt/jwt.xhtml</a>
   *
   * @return JWT encoded token
   */
  default String generateToken(JsonObject claims) {
    return generateToken(claims, new JWTOptions());
  }
}
