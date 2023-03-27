package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.impl.AuthorizationPolicyProviderImpl;

import java.util.List;

@VertxGen
public interface AuthorizationPolicyProvider extends AuthorizationProvider {

  static AuthorizationPolicyProvider create() {
    return new AuthorizationPolicyProviderImpl();
  }

  @Fluent
  AuthorizationPolicyProvider addPolicy(Policy policy);

  @Fluent
  AuthorizationPolicyProvider setPolicies(List<Policy> policies);

  @Fluent
  AuthorizationPolicyProvider clear();
}
