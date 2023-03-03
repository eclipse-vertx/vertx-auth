package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.impl.AuthorizationPolicyProviderImpl;

@VertxGen
public interface AuthorizationPolicyProvider extends AuthorizationProvider {

  static AuthorizationPolicyProvider create(String principalPath, JsonObject policy) {
    return new AuthorizationPolicyProviderImpl(principalPath, policy);
  }
}
