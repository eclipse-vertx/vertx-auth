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

import io.vertx.ext.auth.authorization.AndAuthorization;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.AuthorizationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AndAuthorizationImpl implements AndAuthorization {

  private final List<Authorization> authorizations;

  public AndAuthorizationImpl() {
    this.authorizations = new ArrayList<>();
  }

  @Override
  public AndAuthorization addAuthorization(Authorization authorization) {
    this.authorizations.add(Objects.requireNonNull(authorization));
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof AndAuthorizationImpl))
      return false;
    AndAuthorizationImpl other = (AndAuthorizationImpl) obj;
    return Objects.equals(authorizations, other.authorizations);
  }

  @Override
  public List<Authorization> getAuthorizations() {
    return authorizations;
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizations);
  }

  @Override
  public boolean match(AuthorizationContext context) {
    Objects.requireNonNull(context);

    for (Authorization authorization : authorizations) {
      if (!authorization.match(context)) {
        return false;
      }
    }
    return true;
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    Objects.requireNonNull(otherAuthorization);

    boolean match = false;
    if (otherAuthorization instanceof AndAuthorization) {
      // is there at least one authorization that implies each others authorizations
      for (Authorization otherAndAuthorization : ((AndAuthorization) otherAuthorization).getAuthorizations()) {
        for (Authorization authorization : authorizations) {
          if (authorization.verify(otherAndAuthorization)) {
            match = true;
            break;
          }
        }
      }
    } else {
      for (Authorization authorization : authorizations) {
        if (authorization.verify(otherAuthorization)) {
          match = true;
          break;
        }
      }
      return match;
    }
    return match;
  }

}
