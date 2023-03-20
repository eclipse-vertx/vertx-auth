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

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.OrAuthorization;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class OrAuthorizationImpl implements OrAuthorization {

  private final List<Authorization> authorizations;

  public OrAuthorizationImpl() {
    this.authorizations = new ArrayList<>();
  }

  @Override
  public OrAuthorization addAuthorization(Authorization authorization) {
    this.authorizations.add(Objects.requireNonNull(authorization));
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof OrAuthorizationImpl))
      return false;
    OrAuthorizationImpl other = (OrAuthorizationImpl) obj;
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
      if (authorization.match(context)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    Objects.requireNonNull(otherAuthorization);

    if (otherAuthorization instanceof OrAuthorization) {
      return this.equals(otherAuthorization);
    } else if (authorizations.size() == 1) {
      return authorizations.get(0).verify(otherAuthorization);
    }
    return false;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("OR(");
    for (int i = 0; i < authorizations.size(); i++) {
      if (i > 0)
        sb.append(", ");
      sb.append(authorizations.get(i).toString());
    }
    sb.append(")");
    return sb.toString();
  }
}
