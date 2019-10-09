package io.vertx.ext.auth.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import io.vertx.ext.auth.AndAuthorization;
import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;

public class AndAuthorizationImpl implements AndAuthorization {

	private List<Authorization> authorizations;
	
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

		for (Authorization authorization: authorizations) {
			if (!authorization.match(context)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean implies(Authorization otherAuthorization) {
		Objects.requireNonNull(otherAuthorization);

		boolean match = false;
		if (otherAuthorization instanceof AndAuthorization) {
			// is there at least one authorization that implies each others authorizations 
			for (Authorization otherAndAuthorization: ((AndAuthorization) otherAuthorization).getAuthorizations()) {
				for (Authorization authorization: authorizations) {
					if (authorization.implies(otherAndAuthorization)) {
						match = true;
						break;
					}
				}
			}
		}
		else {
			for (Authorization authorization: authorizations) {
				if (authorization.implies(otherAuthorization)) {
					match = true;
					break;
				}
			}
			return match;
		}
		return match;
	}

}
