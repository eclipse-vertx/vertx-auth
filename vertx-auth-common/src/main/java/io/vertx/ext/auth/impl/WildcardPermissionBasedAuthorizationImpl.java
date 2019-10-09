package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.WildcardPermissionBasedAuthorization;

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

	@Override
	public boolean implies(Authorization otherAuthorization) {
		if (otherAuthorization instanceof WildcardPermissionBasedAuthorizationImpl) {
			WildcardPermissionBasedAuthorizationImpl otherWildcardAuthrization = (WildcardPermissionBasedAuthorizationImpl) otherAuthorization;
			if (wildcardPermission.implies((otherWildcardAuthrization).wildcardPermission)) {
				if (getResource()==null) {
					return true;
				}
				return getResource().equals(otherWildcardAuthrization.getResource());
			}
		}
		return false;
	}

	private WildcardPermissionBasedAuthorization getResolvedAuthorization(AuthorizationContext context) {
		if (resource==null || !resource.hasVariable()) {
			return this;
		}
		return WildcardPermissionBasedAuthorization.create(this.permission).setResource(resource.resolve(context));
	}

	@Override
	public String getResource() {
		return resource!=null ? resource.getValue() : null;
	}

	@Override
	public WildcardPermissionBasedAuthorization setResource(String resource) {
		this.resource = new VariableAwareExpression(Objects.requireNonNull(resource));
		return this;
	}

}
