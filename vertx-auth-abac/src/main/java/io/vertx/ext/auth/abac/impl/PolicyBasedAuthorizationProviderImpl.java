/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.abac.impl;

import io.vertx.core.Future;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.abac.Attribute;
import io.vertx.ext.auth.abac.Policy;
import io.vertx.ext.auth.abac.PolicyBasedAuthorizationProvider;
import io.vertx.ext.auth.authorization.Authorization;

import java.util.*;

public class PolicyBasedAuthorizationProviderImpl implements PolicyBasedAuthorizationProvider {

  private List<Policy> policies;

  public PolicyBasedAuthorizationProviderImpl() {
  }

  @Override
  public String getId() {
    return "policy";
  }

  @Override
  public Future<Void> getAuthorizations(User user) {
    Objects.requireNonNull(user, "user cannot be null");
    Set<Authorization> authorizations = new HashSet<>();

    final List<Policy> policies = this.policies;

    if (policies != null) {
      final int len = policies.size();
      // not using foreach to avoid concurrency issues if policies are added
      // while iterating
      policyLoop: for (int i = 0; i < len; i++) {
        Policy policy = policies.get(i);
        // filter the policies, null subjects means apply all
        // or user subject in the element
        if (policy.getSubjects() != null && !policy.getSubjects().contains(user.subject())) {
          continue;
        }
        if (policy.getAttributes() != null) {
          // if the policy has attributes, we need to match them
          for (Attribute attribute : policy.getAttributes()) {
            if (!attribute.match(user)) {
              continue policyLoop;
            }
          }
        }
        authorizations.addAll(policy.getAuthorizations());
      }
    }
    // put all matching authorizations in the user
    user.authorizations().put(getId(), authorizations);
    return Future.succeededFuture();
  }

  @Override
  public synchronized PolicyBasedAuthorizationProvider addPolicy(Policy policy) {
    if (policies == null) {
      policies = new ArrayList<>();
    }
    policies.add(policy);
    return this;
  }

  @Override
  public synchronized PolicyBasedAuthorizationProvider setPolicies(List<Policy> policies) {
    this.policies = policies;
    return this;
  }

  @Override
  public synchronized PolicyBasedAuthorizationProvider clear() {
    policies = null;
    return this;
  }
}
