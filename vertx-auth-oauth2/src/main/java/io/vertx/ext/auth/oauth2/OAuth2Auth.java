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

package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.impl.AuthProviderInternal;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Auth extends AuthProviderInternal {

  @Override
  default void verifyIsUsingPassword() {
    if (getFlowType() != OAuth2FlowType.PASSWORD) {
      throw new IllegalArgumentException("OAuth2Auth + Basic Auth requires OAuth2 PASSWORD flow");
    }
  }

  /**
   * @deprecated You should use the provider helper {@link io.vertx.ext.auth.oauth2.providers.KeycloakAuth} instead.
   *
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config as exported from the admin console
   * @return the auth provider
   */
  @Deprecated
  static OAuth2Auth createKeycloak(Vertx vertx, OAuth2FlowType flow, JsonObject config) {

    final OAuth2ClientOptions options = new OAuth2ClientOptions();

    // keycloak conversion to oauth2 options
    if (config.containsKey("auth-server-url")) {
      options.setSite(config.getString("auth-server-url"));
    }

    if (config.containsKey("resource")) {
      options.setClientID(config.getString("resource"));
    }

    if (config.containsKey("credentials") && config.getJsonObject("credentials").containsKey("secret")) {
      options.setClientSecret(config.getJsonObject("credentials").getString("secret"));
    }

    if (config.containsKey("public-client") && config.getBoolean("public-client", false)) {
      options.setUseBasicAuthorizationHeader(true);
    }

    if (config.containsKey("realm")) {
      final String realm = config.getString("realm");

      options.setAuthorizationPath("/realms/" + realm + "/protocol/openid-connect/auth");
      options.setTokenPath("/realms/" + realm + "/protocol/openid-connect/token");
      options.setRevocationPath(null);
      options.setLogoutPath("/realms/" + realm + "/protocol/openid-connect/logout");
      options.setUserInfoPath("/realms/" + realm + "/protocol/openid-connect/userinfo");
    }

    if (config.containsKey("realm-public-key")) {
      options.addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("RS256")
        .setPublicKey(config.getString("realm-public-key")));
    }

    return new OAuth2AuthProviderImpl(vertx, options.setFlow(flow));
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @deprecated the flow configuration should be passed in the config object
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  @Deprecated
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) {
    return new OAuth2AuthProviderImpl(vertx, config.setFlow(flow));
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @deprecated the flow configuration should be passed in the config object
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  @Deprecated
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow) {
    return new OAuth2AuthProviderImpl(vertx, new OAuth2ClientOptions().setFlow(flow));
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx) {
    return create(vertx, new OAuth2ClientOptions());
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2ClientOptions config) {
    return new OAuth2AuthProviderImpl(vertx, config);
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   */
  String authorizeURL(JsonObject params);

  /**
   * Returns the Access Token object.
   *
   * @deprecated use {@link AuthProvider#authenticate(JsonObject, Handler)} instead.
   *
   * @param params - JSON with the options, each flow requires different options.
   * @param handler - The handler returning the results.
   */
  @Deprecated
  void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @deprecated use {@link AuthProvider#authenticate(JsonObject, Handler)} instead.
   *
   * @param token the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  @Deprecated
  OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  default OAuth2Auth introspectToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    return introspectToken(token, "access_token", handler);
  }

  /**
   * Query an OAuth 2.0 authorization server to determine the active state of an OAuth 2.0 token and to determine
   * meta-information about this token.
   *
   * @param token the access token (base64 string)
   * @param tokenType hint to the token type e.g.: `access_token`
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
  OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Returns the scope separator.
   *
   * The RFC 6749 states that a scope is expressed as a set of case-sensitive and space-delimited strings, however
   * vendors tend not to agree on this and we see the following cases being used: space, plus sign, comma.
   *
   * @return what value was used in the configuration of the object, falling back to the default value
   * which is a space.
   */
  @Deprecated
  String getScopeSeparator();

  /**
   * Returns the configured flow type for the Oauth2 provider.
   *
   * @return the flow type.
   */
  OAuth2FlowType getFlowType();

  /**
   * Loads a JWK Set from the remote provider.
   *
   * When calling this method several times, the loaded JWKs are updated in the underlying JWT object.
   */
  @Fluent
  OAuth2Auth loadJWK(Handler<AsyncResult<Void>> handler);

  @Fluent
  OAuth2Auth rbacHandler(OAuth2RBAC rbac);
}
