/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 1
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization.impl;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;

public class AuthorizationsImpl implements Authorizations {

  private Map<String, Set<Authorization>> authorizations;

  public AuthorizationsImpl() {
    this.authorizations = new HashMap<>();
  }

  @Override
  public Authorizations add(String providerId, Authorization authorization) {
    Objects.requireNonNull(providerId);
    Objects.requireNonNull(authorization);

    getOrCreateAuthorizations(providerId).add(authorization);
    return this;
  }

  @Override
  public Authorizations add(String providerId, Set<Authorization> authorizations) {
    Objects.requireNonNull(providerId);
    Objects.requireNonNull(authorizations);

    getOrCreateAuthorizations(providerId).addAll(authorizations);
    return this;
  }

  @Override
  public Authorizations delete(String providerId) {
    Objects.requireNonNull(providerId);

    authorizations.remove(providerId);
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof AuthorizationsImpl))
      return false;
    AuthorizationsImpl other = (AuthorizationsImpl) obj;
    if (authorizations == null) {
      if (other.authorizations != null)
        return false;
    } else if (!authorizations.equals(other.authorizations))
      return false;
    return true;
  }

  @Override
  public Set<Authorization> get(String providerId) {
    Objects.requireNonNull(providerId);

    return authorizations.get(providerId);
  }

  private Set<Authorization> getOrCreateAuthorizations(String providerId) {
    Set<Authorization> result = authorizations.computeIfAbsent(providerId, k -> new HashSet<>());
    return result;
  }

  @Override
  public Set<String> getProviderIds() {
    return authorizations.keySet();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((authorizations == null) ? 0 : authorizations.hashCode());
    return result;
  }

}
