package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;

@VertxGen
public interface ClientRegistrationProvider {
  Future<DCRResponse> create(String clientId);
  Future<DCRResponse> get(DCRRequest dcrRequest);
  Future<Void> delete(DCRRequest dcrRequest);
}