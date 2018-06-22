package io.vertx.ext.auth.oauth2.rbac;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.RBACHandler;
import io.vertx.ext.auth.oauth2.rbac.impl.KeycloakRBACImpl;

@VertxGen
public interface KeycloakRBAC extends RBACHandler {

  static KeycloakRBAC create(OAuth2ClientOptions options) {
    return new KeycloakRBACImpl(options);
  }
}
