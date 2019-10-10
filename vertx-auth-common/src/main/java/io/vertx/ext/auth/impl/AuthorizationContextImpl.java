package io.vertx.ext.auth.impl;

import java.util.Objects;

import io.vertx.core.MultiMap;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.User;

public class AuthorizationContextImpl implements AuthorizationContext {

  private User user;
  private MultiMap variables;

  public AuthorizationContextImpl(User user) {
    this(user, MultiMap.caseInsensitiveMultiMap());
  }

  public AuthorizationContextImpl(User user, MultiMap variables) {
    this.user = Objects.requireNonNull(user);
    this.variables = Objects.requireNonNull(variables);
  }

  @Override
  public User user() {
    return user;
  }

  @Override
  public MultiMap variables() {
    return variables;
  }

}
