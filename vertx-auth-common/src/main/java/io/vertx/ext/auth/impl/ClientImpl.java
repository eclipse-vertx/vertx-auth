package io.vertx.ext.auth.impl;

import io.vertx.ext.auth.Client;
import java.util.List;

/**
 * Default implementation of {@link Client}
 */

public class ClientImpl implements Client {

  /**
   * The name of the Client.
   */
  private final String name;

  /**
   * client_credentials is the only grant type supported at this time.
   */
  private final List<GrantType> grantTypes;

  /**
   * Client's authentication methods.
   */
  private final AuthMethod tokenEndpointAuthMethod;

  public ClientImpl(final String name, final List<GrantType> grantTypes,
    final AuthMethod tokenEndpointAuthMethod) {
    assert name != null;
    assert grantTypes != null;
    assert !grantTypes.isEmpty();
    assert tokenEndpointAuthMethod != null;
    this.name = name;
    this.grantTypes = grantTypes;
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }

  @Override
  public String name() {
    return this.name;
  }

  @Override
  public List<GrantType> grantTypes() {
    return this.grantTypes;
  }

  @Override
  public AuthMethod authMethod() {
    return tokenEndpointAuthMethod;
  }

  public enum GrantType {
    client_credentials;
  }

  public enum AuthMethod {
    client_secret_basic,
    client_secret_post,
    client_secret_jwt,
    private_key_jwt,
    none;
  }

}
