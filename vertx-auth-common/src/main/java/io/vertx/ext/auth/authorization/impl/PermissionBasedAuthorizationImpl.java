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

import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.*;

import java.util.Objects;

public class PermissionBasedAuthorizationImpl implements PermissionBasedAuthorization {

  private final String permission;
  private VariableAwareExpression resource;

  public PermissionBasedAuthorizationImpl(String permission) {
    this.permission = Objects.requireNonNull(permission);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof PermissionBasedAuthorizationImpl))
      return false;
    PermissionBasedAuthorizationImpl other = (PermissionBasedAuthorizationImpl) obj;
    return Objects.equals(permission, other.permission) && Objects.equals(resource, other.resource);
  }

  @Override
  public String getPermission() {
    return permission;
  }

  @Override
  public int hashCode() {
    return Objects.hash(permission, resource);
  }

  @Override
  public boolean match(AuthorizationContext context) {
    Objects.requireNonNull(context);

    User user = context.user();
    if (user != null) {
      final Authorization resolvedAuthorization = getResolvedAuthorization(context);
      return user.authorizations()
        .verify(resolvedAuthorization);
    }
    return false;
  }

  private PermissionBasedAuthorization getResolvedAuthorization(AuthorizationContext context) {
    if (resource == null || !resource.hasVariable()) {
      return this;
    }
    return PermissionBasedAuthorization.create(this.permission).setResource(resource.resolve(context));
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    Objects.requireNonNull(otherAuthorization);

    if (otherAuthorization instanceof PermissionBasedAuthorization) {
      PermissionBasedAuthorization otherPermissionBasedAuthorization = (PermissionBasedAuthorization) otherAuthorization;
      if (permission.equals(otherPermissionBasedAuthorization.getPermission())) {
        if (getResource() == null) {
          return otherPermissionBasedAuthorization.getResource() == null;
        }
        return getResource().equals(otherPermissionBasedAuthorization.getResource());
      }
    } else if (otherAuthorization instanceof WildcardPermissionBasedAuthorization) {
      WildcardPermissionBasedAuthorization otherWildcardPermissionBasedAuthorization = (WildcardPermissionBasedAuthorization) otherAuthorization;
      if (permission.equals(otherWildcardPermissionBasedAuthorization.getPermission())) {
        if (getResource() == null) {
          return otherWildcardPermissionBasedAuthorization.getResource() == null;
        }
        return getResource().equals(otherWildcardPermissionBasedAuthorization.getResource());
      }
    }
    return false;
  }

  @Override
  public String getResource() {
    return resource != null ? resource.getValue() : null;
  }

  @Override
  public PermissionBasedAuthorization setResource(String resource) {
    Objects.requireNonNull(resource);
    this.resource = new VariableAwareExpression(resource);
    return this;
  }

  @Override
  public String toString() {
    return "PERMISSION[" + permission + "]";
  }
}
