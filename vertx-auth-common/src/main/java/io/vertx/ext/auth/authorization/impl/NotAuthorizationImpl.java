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

import java.util.Objects;

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.NotAuthorization;

public class NotAuthorizationImpl implements NotAuthorization {

  private Authorization authorization;

  public NotAuthorizationImpl() {
  }

  public NotAuthorizationImpl(Authorization authorization) {
    this.authorization = Objects.requireNonNull(authorization);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof NotAuthorizationImpl))
      return false;
    NotAuthorizationImpl other = (NotAuthorizationImpl) obj;
    return Objects.equals(authorization, other.authorization);
  }

  @Override
  public Authorization getAuthorization() {
    return authorization;
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorization);
  }

  @Override
  public boolean match(AuthorizationContext context) {
    Objects.requireNonNull(context);

    return !this.authorization.match(context);
  }

  @Override
  public boolean verify(Authorization authorization) {
    return this.equals(authorization);
  }

}
