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

import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class AuthorizationsImpl implements Authorizations {

  private Map<String, Set<Authorization>> authorizations;

  @Override
  public synchronized Authorizations add(String providerId, Authorization authorization) {
    Objects.requireNonNull(authorization);

    if (this.authorizations == null) {
      this.authorizations = new HashMap<>();
    } else {
      this.authorizations = new HashMap<>(this.authorizations);
    }
    authorizations
      .computeIfAbsent(providerId, k -> new HashSet<>())
      .add(authorization);

    return this;
  }

  @Override
  public synchronized Authorizations put(String providerId, Set<Authorization> authorizations) {
    Objects.requireNonNull(providerId);
    if (this.authorizations == null) {
      this.authorizations = new HashMap<>();
    } else {
      this.authorizations = new HashMap<>(this.authorizations);
    }
    if (authorizations == null) {
      this.authorizations.remove(providerId);
    } else {
      this.authorizations.put(providerId, Collections.unmodifiableSet(authorizations));
    }

    return this;
  }

  @Override
  public boolean isEmpty() {
    return authorizations == null || authorizations.isEmpty();
  }

  @Override
  public synchronized Authorizations clear(String providerId) {
    Objects.requireNonNull(providerId);
    if (authorizations != null) {
      authorizations = new HashMap<>(authorizations);
      authorizations.remove(providerId);
    }
    return this;
  }

  @Override
  public synchronized Authorizations clearAll() {
    authorizations = null;
    return this;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (!(obj instanceof AuthorizationsImpl))
      return false;
    AuthorizationsImpl other = (AuthorizationsImpl) obj;

    return Objects.equals(authorizations, other.authorizations);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Objects.hashCode(authorizations);
    return result;
  }

  @Override
  public boolean verify(Authorization resolvedAuthorization) {
    if (authorizations == null) {
      return false;
    }

    for (Map.Entry<String, Set<Authorization>> kv : authorizations.entrySet()) {
      for (Authorization authorization : kv.getValue()) {
        if (authorization.verify(resolvedAuthorization)) {
          return true;
        }
      }
    }
    return false;
  }

  @Override
  public Authorizations forEach(BiConsumer<String, Authorization> consumer) {
    if (authorizations == null) {
      return this;
    }

    for (Map.Entry<String, Set<Authorization>> kv : authorizations.entrySet()) {
      for (Authorization authorization : kv.getValue()) {
        consumer.accept(kv.getKey(), authorization);
      }
    }
    return this;
  }

  @Override
  public Authorizations forEach(String providerId, Consumer<Authorization> consumer) {
    if (authorizations == null) {
      return this;
    }

    authorizations
      .getOrDefault(providerId, Collections.emptySet())
      .forEach(consumer);
    return this;
  }
}
