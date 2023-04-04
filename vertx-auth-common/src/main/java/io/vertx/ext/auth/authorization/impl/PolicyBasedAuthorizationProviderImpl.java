package io.vertx.ext.auth.authorization.impl;

import io.vertx.core.Future;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Attribute;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.PolicyBasedAuthorizationProvider;
import io.vertx.ext.auth.authorization.Policy;

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
