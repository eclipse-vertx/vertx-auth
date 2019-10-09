package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.NotAuthorization;

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
	public boolean implies(Authorization authorization) {
		return this.equals(authorization) ? true : false;
	}

}
