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

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;

public class AuthorizationsImpl implements Authorizations {

  private final Map<String, Set<Authorization>> authorizations;

  public AuthorizationsImpl() {
    // store the authorizations as a concurrent hash map, mainly because this
    // will be linked to a user object. In this case, we can't guarantee that
    // concurrent access is safe.
    this.authorizations = new ConcurrentHashMap<>();
  }

  @Override
  public Authorizations add(String providerId, Authorization authorization) {
    Objects.requireNonNull(authorization);
    return add(providerId, Collections.singleton(authorization));
  }

  @Override
  public Authorizations add(String providerId, Set<Authorization> authorizations) {
    Objects.requireNonNull(providerId);
    Objects.requireNonNull(authorizations);

    ConcurrentHashMap.KeySetView<Authorization, Boolean> concurrentAuthorizations = ConcurrentHashMap.newKeySet();
    concurrentAuthorizations.addAll(authorizations);

    getOrCreateAuthorizations(providerId)
      .addAll(concurrentAuthorizations);
    return this;
  }

  @Override
  public Authorizations clear(String providerId) {
    Objects.requireNonNull(providerId);

    authorizations.remove(providerId);
    return this;
  }

  @Override
  public Authorizations clear() {
    authorizations.clear();
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof AuthorizationsImpl))
      return false;
    AuthorizationsImpl other = (AuthorizationsImpl) obj;

    return authorizations.equals(other.authorizations);
  }

  @Override
  public Set<Authorization> get(String providerId) {
    Objects.requireNonNull(providerId);

    final Set<Authorization> set = authorizations.get(providerId);
    if (set == null) {
      return Collections.emptySet();
    }

    return set;
  }

  private Set<Authorization> getOrCreateAuthorizations(String providerId) {
    return authorizations.computeIfAbsent(providerId, k -> ConcurrentHashMap.newKeySet());
  }

  @Override
  public Set<String> getProviderIds() {
    return authorizations.keySet();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + authorizations.hashCode();
    return result;
  }

}
