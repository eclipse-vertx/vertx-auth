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
package io.vertx.ext.auth.jwt.authorization;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.jwt.authorization.impl.JWTAuthorizationImpl;

/**
 * Implementation of the JWT authorization provider.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface JWTAuthorization extends AuthorizationProvider {

  /**
   * Factory method to create a Authorization provider for JWT tokens.
   * @param rootClaim slash separated string to the json array with the claims.
   * @return a AuthorizationProvider
   */
  static JWTAuthorization create(String rootClaim) {
    return new JWTAuthorizationImpl(rootClaim);
  }
}
