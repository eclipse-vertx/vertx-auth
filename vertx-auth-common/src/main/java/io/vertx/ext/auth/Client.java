package io.vertx.ext.auth;

import io.vertx.ext.auth.impl.ClientImpl;
import io.vertx.ext.auth.impl.ClientImpl.AuthMethod;
import io.vertx.ext.auth.impl.ClientImpl.GrantType;
import java.util.List;

/**
 * Represents an authenticates User and contains operations to authorise the user.
 */

public interface Client {

  static ClientImpl create(final String name, final List<GrantType> grantTypes,
    final AuthMethod tokenEndpointAuthMethod) {
    return new ClientImpl(name, grantTypes, tokenEndpointAuthMethod);
  }

  static ClientImpl create(final String name, final GrantType grantType,
    final AuthMethod tokenEndpointAuthMethod) {
    return new ClientImpl(name, List.of(grantType), tokenEndpointAuthMethod);
  }

  String name();

  List<GrantType> grantTypes();

  AuthMethod authMethod();
}
