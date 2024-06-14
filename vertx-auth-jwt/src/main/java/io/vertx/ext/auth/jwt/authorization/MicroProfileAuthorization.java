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
import io.vertx.ext.auth.user.User;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.jwt.authorization.impl.MicroProfileAuthorizationImpl;

/**
 * Implementation of the Microprofile MP-JWT 1.1 RBAC based on the access token groups key.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface MicroProfileAuthorization extends AuthorizationProvider {

  /**
   * Factory method to create a Authorization provider for tokens adhering to the MP-JWT 1.1 spec.
   * When the user is known to not be a JWT, (e.g.: a OAuth2 response token) then the root claim
   * is expected to be extracted from {@link User#attributes()} under the key {@code accessToken}.
   *
   * @return a AuthorizationProvider
   */
  static MicroProfileAuthorization create() {
    return new MicroProfileAuthorizationImpl();
  }
}
