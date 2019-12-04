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
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.WildcardPermissionBasedAuthorization;

public class WildcardPermissionBasedAuthorizationImpl implements WildcardPermissionBasedAuthorization {

  private String permission;
  private VariableAwareExpression resource;
  private transient WildcardExpression wildcardPermission;

  public WildcardPermissionBasedAuthorizationImpl(String permission) {
    this.permission = Objects.requireNonNull(permission);
    this.wildcardPermission = new WildcardExpression(permission);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof WildcardPermissionBasedAuthorizationImpl))
      return false;
    WildcardPermissionBasedAuthorizationImpl other = (WildcardPermissionBasedAuthorizationImpl) obj;
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
      Authorization resolvedAuthorization = getResolvedAuthorization(context);
      for (String providerId: user.authorizations().getProviderIds()) {
        for (Authorization authorization : user.authorizations().get(providerId)) {
          if (authorization.verify(resolvedAuthorization)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    if (otherAuthorization instanceof WildcardPermissionBasedAuthorizationImpl) {
      WildcardPermissionBasedAuthorizationImpl otherWildcardPermission = (WildcardPermissionBasedAuthorizationImpl) otherAuthorization;
      if (wildcardPermission.implies((otherWildcardPermission).wildcardPermission)) {
        if (getResource() == null) {
          return true;
        }
        return getResource().equals(otherWildcardPermission.getResource());
      }
    }
    else if (otherAuthorization instanceof PermissionBasedAuthorization) {
      PermissionBasedAuthorization otherPermission = (PermissionBasedAuthorization) otherAuthorization;
      if (this.permission.equals(otherPermission.getPermission())) {
        if (getResource() == null) {
          return true;
        }
        return getResource().equals(otherPermission.getResource());
      }
    }
    return false;
  }

  private WildcardPermissionBasedAuthorization getResolvedAuthorization(AuthorizationContext context) {
    if (resource == null || !resource.hasVariable()) {
      return this;
    }
    return WildcardPermissionBasedAuthorization.create(this.permission).setResource(resource.resolve(context));
  }

  @Override
  public String getResource() {
    return resource != null ? resource.getValue() : null;
  }

  @Override
  public WildcardPermissionBasedAuthorization setResource(String resource) {
    this.resource = new VariableAwareExpression(Objects.requireNonNull(resource));
    return this;
  }

}
