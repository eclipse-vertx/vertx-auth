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
package io.vertx.ext.auth.oauth2.rbac;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2RBAC;
import io.vertx.ext.auth.oauth2.rbac.impl.KeycloakRBACImpl;

/**
 * Implementation of the Keycloak RBAC handler.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface KeycloakRBAC {

  /**
   * Factory method to create a RBAC handler for tokens adhering to the Keycloak token format.
   * @return a RBAC validator
   */
  static OAuth2RBAC create(OAuth2ClientOptions options) {
    return new KeycloakRBACImpl(options);
  }
}
