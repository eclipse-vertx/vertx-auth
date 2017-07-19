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
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.impl.OAuth2AuthProviderImpl;

/**
 * Factory interface for creating OAuth2 based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface OAuth2Auth extends AuthProvider {

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
      options.setPubSecKeyOptions(new PubSecKeyOptions()
        .setType("RS256")
        .setPublicKey(config.getString("realm-public-key")));
      options.setJwtToken(true);
    }

    return new OAuth2AuthProviderImpl(vertx, flow, options);
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @param config  the config
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow, OAuth2ClientOptions config) {
    return new OAuth2AuthProviderImpl(vertx, flow, config);
  }

  /**
   * Create a OAuth2 auth provider
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static OAuth2Auth create(Vertx vertx, OAuth2FlowType flow) {
    return new OAuth2AuthProviderImpl(vertx, flow, new OAuth2ClientOptions());
  }

  /**
   * Generate a redirect URL to the authN/Z backend. It only applies to auth_code flow.
   */
  String authorizeURL(JsonObject params);

  /**
   * Returns the Access Token object.
   *
   * @param params - JSON with the options, each flow requires different options.
   * @param handler - The handler returning the results.
   */
  void getToken(JsonObject params, Handler<AsyncResult<AccessToken>> handler);

  /**
   * Call OAuth2 APIs.
   *
   * @param method HttpMethod
   * @param path target path
   * @param params parameters
   * @param handler handler
   * @return self
   */
  @Fluent
  OAuth2Auth api(HttpMethod method, String path, JsonObject params, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Returns true if this provider supports JWT tokens as the access_token. This is typically true if the provider
   * implements the `openid-connect` protocol. This is a plain return from the config option jwtToken, which is false
   * by default.
   *
   * This information is important to validate grants. Since pure OAuth2 should be used for authorization and when a
   * token is requested all grants should be declared, in case of openid-connect this is not true. OpenId will issue
   * a token and all grants will be encoded on the token itself so the requester does not need to list the required
   * grants.
   *
   * @return true if openid-connect is used.
   */
  boolean hasJWTToken();


  /**
   * Decode a token to a {@link AccessToken} object. This is useful to handle bearer JWT tokens.
   *
   * @param token the access token (base64 string)
   * @param handler A handler to receive the event
   * @return self
   */
  @Fluent
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
  OAuth2Auth introspectToken(String token, Handler<AsyncResult<AccessToken>> handler);

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
  OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Returns the scope separator.
   *
   * The RFC 6749 states that a scope is expressed as a set of case-sensitive and space-delimited strings, however
   * vendors tend not to agree on this and we see the following cases being used: space, plus sign, comma.
   *
   * @return what value was used in the configuration of the object, falling back to the default value
   * which is a space.
   */
  String getScopeSeparator();

  /**
   * Returns the configured flow type for the Oauth2 provider.
   *
   * @return the flow type.
   */
  OAuth2FlowType getFlowType();
}
