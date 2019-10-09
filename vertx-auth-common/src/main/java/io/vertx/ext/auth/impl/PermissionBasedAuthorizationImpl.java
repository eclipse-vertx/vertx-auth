package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.PermissionBasedAuthorization;
import io.vertx.ext.auth.User;

public class PermissionBasedAuthorizationImpl implements PermissionBasedAuthorization {

	private String permission;
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
		if (user!=null) {
			Authorization resolvedAuthorization = getResolvedAuthorization(context); 
			for (Authorization authorization: user.authorizations()) {
				if (authorization.implies(resolvedAuthorization)) {
					return true;
				}
			}
		}
		return false;
	}

	private PermissionBasedAuthorization getResolvedAuthorization(AuthorizationContext context) {
		if (resource==null || !resource.hasVariable()) {
			return this;
		}
		return PermissionBasedAuthorization.create(this.permission).setResource(resource.resolve(context));
	}

	@Override
	public boolean implies(Authorization otherAuthorization) {
		Objects.requireNonNull(otherAuthorization);
		
		if (otherAuthorization instanceof PermissionBasedAuthorization) {
			PermissionBasedAuthorization otherPermissionBasedAuthorization = (PermissionBasedAuthorization) otherAuthorization;
			if (permission.equals(otherPermissionBasedAuthorization.getPermission())) {
				if (getResource()==null) {
					return otherPermissionBasedAuthorization.getResource()==null;
				}
				return getResource().equals(otherPermissionBasedAuthorization.getResource());
			}
		}
		return false;
	}

	@Override
	public String getResource() {
		return resource!=null ? resource.getValue() : null;
	}

	@Override
	public PermissionBasedAuthorization setResource(String resource) {
		Objects.requireNonNull(resource);
		this.resource = new VariableAwareExpression(resource);
		return this;
	}

}
