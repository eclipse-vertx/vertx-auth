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
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.authorization.impl.KeycloakAuthorizationImpl;

/**
 * Implementation of the Keycloak Authorization Provider.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface KeycloakAuthorization extends AuthorizationProvider {

  /**
   * Factory method to create an Authorization Provider for tokens adhering to the Keycloak token format.
   * When the user is known to not be a JWT, (e.g.: a OAuth2 response token) then the root claim
   * is expected to be the extracted from the user {@link User#attributes()} under the key: {@code accessToken}.
   *
   * @return a AuthorizationProvider
   */
  static KeycloakAuthorization create() {
    return new KeycloakAuthorizationImpl();
  }
}
