package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.User;

public class AuthorizationContextImpl implements AuthorizationContext {

	private User user;
	private HttpServerRequest request;

	public AuthorizationContextImpl(User user) {
		this.user = Objects.requireNonNull(user);
	}

	public AuthorizationContextImpl(User user, HttpServerRequest request) {
		this.user = Objects.requireNonNull(user);
		this.request = Objects.requireNonNull(request);
	}
	
	@Override
	public User user() {
		return user;
	}

	@Override
	public HttpServerRequest request() {
		return request;
	}

}
