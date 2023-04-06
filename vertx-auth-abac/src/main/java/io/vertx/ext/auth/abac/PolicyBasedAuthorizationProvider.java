package io.vertx.ext.auth.abac;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.abac.impl.PolicyBasedAuthorizationProviderImpl;

import java.util.List;

@VertxGen
public interface PolicyBasedAuthorizationProvider extends AuthorizationProvider {

  static PolicyBasedAuthorizationProvider create() {
    return new PolicyBasedAuthorizationProviderImpl();
  }

  @Fluent
  PolicyBasedAuthorizationProvider addPolicy(Policy policy);

  @Fluent
  PolicyBasedAuthorizationProvider setPolicies(List<Policy> policies);

  @Fluent
  PolicyBasedAuthorizationProvider clear();
}
