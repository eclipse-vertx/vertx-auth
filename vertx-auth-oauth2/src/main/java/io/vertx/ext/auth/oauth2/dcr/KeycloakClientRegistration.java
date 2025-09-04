package io.vertx.ext.auth.oauth2.dcr;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.ClientRegistrationProvider;
import io.vertx.ext.auth.oauth2.DCROptions;
import io.vertx.ext.auth.oauth2.dcr.impl.KeycloakClientRegistrationImpl;

public interface KeycloakClientRegistration extends ClientRegistrationProvider {

  static KeycloakClientRegistration create(Vertx vertx, DCROptions dcrOptions) {
    return new KeycloakClientRegistrationImpl(vertx, dcrOptions);
  }
}