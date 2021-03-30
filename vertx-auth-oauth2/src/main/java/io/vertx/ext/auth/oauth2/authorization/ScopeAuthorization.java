/*
 * Copyright 2015 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.oauth2.authorization;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.oauth2.authorization.impl.ScopeAuthorizationImpl;

import java.util.List;

/**
 * Scope is a mechanism in OAuth 2.0 to limit an application's access to a user's account.
 * An application can request one or more scopes, this information is then presented to the
 * user in the consent screen, and the access token issued to the application will be
 * limited to the scopes granted.
 *
 * The OAuth spec allows the authorization server or user to modify the scopes granted to
 * the application compared to what is requested, although there are not many examples of
 * services doing this in practice.
 *
 * OAuth2 does not define any particular values for scopes, since it is highly dependent
 * on the service's internal architecture and needs.
 *
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>.
 */
@VertxGen
public interface ScopeAuthorization extends AuthorizationProvider {

  /**
   * Factory method to create a Authorization provider for Oauth 2.0 scopes using the default separator {@code " "}.
   *
   * @return a AuthorizationProvider
   */
  static ScopeAuthorization create() {
    return new ScopeAuthorizationImpl(" ", null);
  }

  /**
   * Factory method to create a Authorization provider for Oauth 2.0 scopes.
   *
   * @param scopeSeparator the scope separator e.g.: {@code " "}, {@code ","}, {@code "+"}
   * @return a AuthorizationProvider
   */
  static ScopeAuthorization create(String scopeSeparator) {
    return new ScopeAuthorizationImpl(scopeSeparator, null);
  }

  /**
   * Factory method to create a Authorization provider for OpenID Connect scopes. The claim key will be used to locate
   * the scopes from a decoded JWT.
   *
   * @param scopeSeparator the scope separator e.g.: {@code " "}, {@code ","}, {@code "+"}
   * @param claimKey the scope claim key e.g.: {@code "scp"}, {@code "scope"}
   * @return a AuthorizationProvider
   */
  static ScopeAuthorization create(String scopeSeparator, String claimKey) {
    return new ScopeAuthorizationImpl(scopeSeparator, claimKey);
  }

  /**
   * Returns the configured separator.
   *
   * @return the separator.
   */
  String separator();

  /**
   * Returns the configured claim key.
   *
   * @return the claim key.
   */
  String claimKey();

  /**
   * Returns a String with the given scopes concatenated with the given separator.
   * @param scopes a list of scopes
   * @return concatenated string.
   */
  String encode(List<String> scopes);
}
