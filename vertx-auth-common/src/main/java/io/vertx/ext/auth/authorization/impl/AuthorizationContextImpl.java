/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.MultiMap;
import io.vertx.ext.auth.user.User;
import io.vertx.ext.auth.authorization.AuthorizationContext;

import java.util.Objects;

public class AuthorizationContextImpl implements AuthorizationContext {

  private final User user;
  private final MultiMap variables;

  public AuthorizationContextImpl(User user, MultiMap variables) {
    this.user = Objects.requireNonNull(user);
    this.variables = Objects.requireNonNull(variables);
  }

  @Override
  public User user() {
    return user;
  }

  @Override
  public MultiMap variables() {
    return variables;
  }

}
