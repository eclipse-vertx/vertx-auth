package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.RoleBasedAuthorization;
import io.vertx.ext.auth.User;

public class RoleBasedAuthorizationImpl implements RoleBasedAuthorization {

  private String role;
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
      for (Authorization authorization : user.authorizations()) {
        if (authorization.verify(resolvedAuthorization)) {
          return true;
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
