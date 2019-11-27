package io.vertx.ext.auth;

import java.util.Set;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;

@VertxGen
public interface Authorizations {

  @Fluent
  Authorizations add(String providerId, Set<Authorization> authorizations);

  @Fluent
  Authorizations add(String providerId, Authorization authorization);

  @Fluent
  Authorizations delete(String providerId);

  Set<Authorization> get(String providerId);

  Set<String> getProviderIds();

}
