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
  public synchronized Authorizations put(String providerId, Set<Authorization> _authorizations) {
    Objects.requireNonNull(providerId);
    Map<String, Set<Authorization>> authorizations = this.authorizations;
    if (authorizations == null) {
      if (_authorizations != null) {
        authorizations = new HashMap<>();
      }
    } else {
      authorizations = new HashMap<>(authorizations);
      if (_authorizations == null) {
        authorizations.remove(providerId);
      }
    }
    if (_authorizations != null) {
      authorizations
        .put(providerId, Collections.unmodifiableSet(_authorizations));
    }

    // swap
    this.authorizations = authorizations;
    return this;
  }

  @Override
  public synchronized Authorizations putAll(Map<String, Set<Authorization>> authorizations) {
    Objects.requireNonNull(authorizations);
    this.authorizations = authorizations;
    return this;
  }

  @Override
  public synchronized Authorizations clear() {
    authorizations = null;
    return this;
  }

  @Override
  public boolean contains(String providerId) {
    return authorizations != null && authorizations.containsKey(providerId);
  }

  @Override
  public boolean isEmpty() {
    final Map<String, Set<Authorization>> authorizations = this.authorizations;
    return authorizations == null || authorizations.isEmpty();
  }

  @Override
  public boolean equals(Object obj) {
    final Map<String, Set<Authorization>> authorizations = this.authorizations;

    if (this == obj)
      return true;
    if (!(obj instanceof AuthorizationsImpl))
      return false;
    AuthorizationsImpl other = (AuthorizationsImpl) obj;

    return Objects.equals(authorizations, other.authorizations);
  }

  @Override
  public int hashCode() {
    final Map<String, Set<Authorization>> authorizations = this.authorizations;

    final int prime = 31;
    int result = 1;
    result = prime * result + Objects.hashCode(authorizations);
    return result;
  }

  @Override
  public boolean verify(Authorization resolvedAuthorization) {
    final Map<String, Set<Authorization>> authorizations = this.authorizations;

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
    final Map<String, Set<Authorization>> authorizations = this.authorizations;

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
    final Map<String, Set<Authorization>> authorizations = this.authorizations;

    if (authorizations == null) {
      return this;
    }

    authorizations
      .getOrDefault(providerId, Collections.emptySet())
      .forEach(consumer);
    return this;
  }

  @Override
  public String toString() {
    return authorizations.toString();
  }
}
