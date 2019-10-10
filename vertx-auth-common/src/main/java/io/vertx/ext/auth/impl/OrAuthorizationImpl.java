package io.vertx.ext.auth.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import io.vertx.ext.auth.Authorization;
import io.vertx.ext.auth.AuthorizationContext;
import io.vertx.ext.auth.OrAuthorization;

public class OrAuthorizationImpl implements OrAuthorization {

  private List<Authorization> authorizations;

  public OrAuthorizationImpl() {
    this.authorizations = new ArrayList<>();
  }

  @Override
  public OrAuthorization addAuthorization(Authorization authorization) {
    this.authorizations.add(Objects.requireNonNull(authorization));
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof OrAuthorizationImpl))
      return false;
    OrAuthorizationImpl other = (OrAuthorizationImpl) obj;
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

    for (Authorization authorization : authorizations) {
      if (authorization.match(context)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean verify(Authorization otherAuthorization) {
    Objects.requireNonNull(otherAuthorization);

    if (otherAuthorization instanceof OrAuthorization) {
      return this.equals(otherAuthorization);
    } else if (authorizations.size() == 1) {
      return authorizations.get(0).verify(otherAuthorization);
    }
    return false;
  }

}
