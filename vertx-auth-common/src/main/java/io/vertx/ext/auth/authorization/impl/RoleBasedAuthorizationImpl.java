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
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.AuthorizationContext;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;

import java.util.Objects;

public class RoleBasedAuthorizationImpl implements RoleBasedAuthorization {

  private final String role;
  private VariableAwareExpression resource;

  public RoleBasedAuthorizationImpl(String role) {
    this.role = Objects.requireNonNull(role);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof RoleBasedAuthorizationImpl))
      return false;
    RoleBasedAuthorizationImpl other = (RoleBasedAuthorizationImpl) obj;
    return Objects.equals(resource, other.resource) && Objects.equals(role, other.role);
  }

  @Override
  public String getRole() {
    return role;
  }

  @Override
  public int hashCode() {
    return Objects.hash(resource, role);
  }

  @Override
  public boolean match(AuthorizationContext context) {
    Objects.requireNonNull(context);

    User user = context.user();
    if (user != null) {
      Authorization resolvedAuthorization = getResolvedAuthorization(context);
      for (String providerId : user.authorizations().getProviderIds()) {
        for (Authorization authorization : user.authorizations().get(providerId)) {
          if (authorization.verify(resolvedAuthorization)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private RoleBasedAuthorization getResolvedAuthorization(AuthorizationContext context) {
    if (resource == null || !resource.hasVariable()) {
      return this;
    }
    return RoleBasedAuthorization.create(this.role).setResource(resource.resolve(context));
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    Objects.requireNonNull(otherAuthorization);

    if (otherAuthorization instanceof RoleBasedAuthorization) {
      RoleBasedAuthorization otherRoleBasedAuthorization = (RoleBasedAuthorization) otherAuthorization;
      if (role.equals(otherRoleBasedAuthorization.getRole())) {
        if (getResource() == null) {
          return otherRoleBasedAuthorization.getResource() == null;
        }
        return getResource().equals(otherRoleBasedAuthorization.getResource());
      }
    }
    return false;
  }

  @Override
  public String getResource() {
    return resource != null ? resource.getValue() : null;
  }

  @Override
  public RoleBasedAuthorization setResource(String resource) {
    Objects.requireNonNull(resource);
    this.resource = new VariableAwareExpression(resource);
    return this;
  }

}
