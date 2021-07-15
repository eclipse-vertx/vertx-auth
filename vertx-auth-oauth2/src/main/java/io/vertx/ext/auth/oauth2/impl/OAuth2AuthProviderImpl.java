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
package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.NoSuchKeyIdException;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.oauth2.*;

import java.util.List;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthProviderImpl.class);

  private final Vertx vertx;
  private final OAuth2Options config;
  private final OAuth2API api;

  // avoid caching, as it may swap,
  // old references are still valid though
  private volatile JWT jwt = new JWT();
  private long updateTimerId = -1;
  private Handler<String> missingKeyHandler;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2Options config) {
    this.vertx = vertx;
    this.config = config;
    this.api = new OAuth2API(vertx, config);
    // compute paths with variables, at this moment it is only relevant that
    // all variables are properly computed
    this.config.replaceVariables(true);
    this.config.validate();

    // set the nonce algorithm
    jwt.nonceAlgorithm(this.config.getJWTOptions().getNonceAlgorithm());

    if (config.getPubSecKeys() != null) {
      for (PubSecKeyOptions pubSecKey : config.getPubSecKeys()) {
        jwt.addJWK(new JWK(pubSecKey));
      }
    }
  }

  @Override
  public OAuth2Auth jWKSet(Handler<AsyncResult<Void>> handler) {
    api.jwkSet(res -> {
      if (res.failed()) {
        handler.handle(Future.failedFuture(res.cause()));
      } else {
        if (updateTimerId != -1) {
          // cancel any running timer to avoid multiple updates
          // it is not important if the timer isn't active anymore

          // this could happen if both the user triggers the update and
          // there's a timer already in progress
          vertx.cancelTimer(updateTimerId);
        }
        final JsonObject json = res.result();
        JWT jwt = new JWT()
          // set the nonce algorithm
          .nonceAlgorithm(config.getJWTOptions().getNonceAlgorithm());

        JsonArray keys = json.getJsonArray("keys");
        for (Object key : keys) {
          try {
            jwt.addJWK(new JWK((JsonObject) key));
          } catch (RuntimeException e) {
            LOG.warn("Skipped unsupported JWK: " + e.getMessage());
          }
        }
        // swap
        synchronized (this) {
          this.jwt = jwt;
        }
        // compute the next update if the server told us too
        if (json.containsKey("maxAge")) {
          // ensure that leeway is never negative
          int leeway = Math.max(0, config.getJWTOptions().getLeeway());
          // delay is in ms, while cache max age is sec
          final long delay = json.getLong("maxAge") * 1000 - leeway;
          // salesforce (for example) sometimes disables the max-age as setting it to 0
          // for these cases we just cancel
          if (delay > 0) {
            this.updateTimerId = vertx.setPeriodic(delay, t ->
              jWKSet(autoUpdateRes -> {
                if (autoUpdateRes.failed()) {
                  LOG.warn("Failed to auto-update JWK Set", autoUpdateRes.cause());
                }
              }));
          } else {
            updateTimerId = -1;
          }
        }
        // return
        handler.handle(Future.succeededFuture());
      }
    });
    return this;
  }

  @Override
  public OAuth2Auth missingKeyHandler(Handler<String> handler) {
    this.missingKeyHandler = handler;
    return this;
  }

  public OAuth2Options getConfig() {
    return config;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> handler) {

    if (authInfo.containsKey("access_token")) {
      TokenCredentials cred = new TokenCredentials(authInfo.getString("access_token"));
      if (authInfo.containsKey("scopes")) {
        for (Object scope : authInfo.getJsonArray("scopes")) {
          cred.addScope((String) scope);
        }
      }
      authenticate(cred, handler);
      return;
    }

    final OAuth2FlowType flow = config.getFlow();
    final Oauth2Credentials cred;

    switch (flow) {
      case AUTH_CODE:
        if (authInfo.containsKey("code")) {
          cred = new Oauth2Credentials()
            .setCode(authInfo.getString("code"))
            .setCodeVerifier(authInfo.getString("codeVerifier"))
            .setRedirectUri(authInfo.getString("redirectUri"));

          authenticate(cred, handler);
          return;
        }
        break;
      case CLIENT:
        cred = new Oauth2Credentials();

        if (authInfo.containsKey("scopes")) {
          for (Object scope : authInfo.getJsonArray("scopes")) {
            cred.addScope((String) scope);
          }
        }

        authenticate(cred, handler);
        return;
      case PASSWORD:
        if (authInfo.containsKey("username") && authInfo.containsKey("password")) {

          cred = new Oauth2Credentials()
            .setUsername(authInfo.getString("username"))
            .setPassword(authInfo.getString("password"));

          if (authInfo.containsKey("scopes")) {
            for (Object scope : authInfo.getJsonArray("scopes")) {
              cred.addScope((String) scope);
            }
          }

          authenticate(cred, handler);
          return;
        }
        break;
      case AUTH_JWT:
      case AAD_OBO:
        if (authInfo.containsKey("assertion")) {
          cred = new Oauth2Credentials()
            .setAssertion(authInfo.getString("assertion"));

          authenticate(cred, handler);
          return;
        }
        authenticate(new Oauth2Credentials().setJwt(authInfo), handler);
        return;
      case IMPLICIT:
      default:
        break;
    }
    // fallback
    handler.handle(Future.failedFuture("can't parse token: " + authInfo));
  }

  /**
   * OAuth2/OIDC authentication. Authentication in this object means, checking if the given credentials are valid by
   * verifying them with the IdP or doing a cryptographic check of the credentials.
   * <p>
   * Depending on the flow in use, different credential objects can be used in this method.
   *
   * <ul>
   *   <li>{@code AUTH_CODE} - The credentials are expected to contain the {@code code} received by the user, and this
   *   method will communicate with the IdP to exchange this code for a {@code access_token}</li>
   *   <li>{@code CLIENT} - The client credentials flow expects that the credential object may contain {@code scopes}.
   *   This flow will use the private configuration {@code clientId} and {@code clientSecret} to request a
   *   {@code access_token}</li>
   *   <li>{@code PASSWORD} - The password flow will use the credentials {@code username} and {@code password} and
   *   optionally {@code scopes} and exchange then for an {@code access_token}</li>
   *   <li>{@code AUTH_JWT/AAD_OBO} - The JWT Bearer flow will exchange a {@code access_token} for another
   *   {@code access_token} in order to perform a action on behalf of the user.</li>
   *   <li>{@code IMPLICIT} - The implicit flow has been deprecated by OAuth2 and was never supported by this module.</li>
   * </ul>
   * <p>
   * This means that different {@link Credentials} types can be used.
   *
   * <ul>
   *   <li>{@link TokenCredentials} - Used for stateless authentication, for example a {@code access_token} from a
   *   client. In this case if the flow is set to @{code AUTH_JWT/AAD_OBO} then the token is traded for a new one. If
   *   the flow is {@code AUTH_CODE/CLIENT/PASSWORD} and there are keys loaded then the token is validated locally</li>
   *   <li>{@link UsernamePasswordCredentials} - This credential can only be used with {@code PASSWORD} flow</li>
   *   <li>{@link Oauth2Credentials} the expected implementation to be used. When one of the above is used, internally
   *   the credential data is converted to this type and used solely in the process.</li>
   * </ul>
   */
  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> handler) {
    try {
      // adapt credential type to be always the expected one
      if (credentials instanceof UsernamePasswordCredentials) {
        UsernamePasswordCredentials usernamePasswordCredentials = (UsernamePasswordCredentials) credentials;
        usernamePasswordCredentials.checkValid(null);

        Oauth2Credentials cred = new Oauth2Credentials()
          .setUsername(usernamePasswordCredentials.getUsername())
          .setPassword(usernamePasswordCredentials.getPassword());

        authenticate(cred, handler);
        return;
      }

      // if the authInfo object already contains a token validate it to confirm that it
      // can be reused, otherwise, based on the configured flow, request a new token
      // from the authority provider

      if (credentials instanceof TokenCredentials) {
        // authInfo contains a non null token
        TokenCredentials tokenCredentials = (TokenCredentials) credentials;
        tokenCredentials.checkValid(null);

        // this validation can be done in 3 different ways:
        // 1) this object flow is JWT, in that case we need to request a new token On-Behalf-Of the original token
        // 2) the token is a JWT and in this case if the provider is OpenId Compliant the token can be verified locally
        // 3) the token is an opaque string and we need to introspect it

        // JWT flow must be checked first. The reason is that IdP could share the same jwks (like Azure) and tokens be
        // valid and the flow would be ignored.

        switch (config.getFlow()) {
          case AUTH_JWT:
          case AAD_OBO:
            // this provider is expected to be working in OBO mode, yet there are no keys loaded or the loaded keys aren't
            // usable with the received token. In this case we need to fetch a new token
            final Oauth2Credentials oboCredentials = new Oauth2Credentials()
              .setAssertion(tokenCredentials.getToken())
              .setJwt(config.getExtraParameters())
              .setScopes(tokenCredentials.getScopes());

            authenticate(oboCredentials, handler);
            return;
        }

        // if the JWT library is working in unsecure mode, local validation is not to be trusted

        final User user = createUser(new JsonObject().put("access_token", tokenCredentials.getToken()), false);

        if (user.attributes().containsKey("accessToken") && !jwt.isUnsecure()) {
          final JWTOptions jwtOptions = config.getJWTOptions();
          // a valid JWT token should have the access token value decoded
          // the token might be valid, but expired
          if (!user.expired(jwtOptions.getLeeway())) {
            // basic validation passed, the token is not expired
            handler.handle(Future.succeededFuture(user));
            return;
          }
        }

        // the token is not in JWT format or this auth provider is not configured for secure JWTs
        // in this case we must rely on token introspection in order to know more about its state
        // attempt to create a token object from the given string representation

        // Not all providers support this so we need to check if the call is possible
        if (config.getIntrospectionPath() == null) {
          // this provider doesn't allow introspection, this means we are not able to perform
          // any authentication,
          if (user.attributes().containsKey("missing-kid")) {
            handler.handle(Future.failedFuture(new NoSuchKeyIdException(user.attributes().getString("missing-kid"))));
          } else {
            handler.handle(Future.failedFuture("Can't authenticate access_token: Provider doesn't support token introspection"));
          }
          return;
        }

        // perform the introspection
        api
          .tokenIntrospection("access_token", tokenCredentials.getToken(), res -> {
            if (res.failed()) {
              handler.handle(Future.failedFuture(res.cause()));
              return;
            }

            final JsonObject json = res.result();

            // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations may not return this)
            if (json.containsKey("active") && !json.getBoolean("active", false)) {
              handler.handle(Future.failedFuture("Inactive Token"));
              return;
            }

            // OPTIONALS

            // validate client id
            if (json.containsKey("client_id")) {
              // response included a client id. Match against config client id
              String clientId = config.getClientId();
              if (clientId != null && !clientId.equals(json.getString("client_id"))) {
                // Client identifier for the OAuth 2.0 client that requested this token.
                LOG.info("Introspect client_id doesn't match configured client_id");
              }
            }

            // attempt to create a user from the json object
            final User newUser = createUser(json, user.attributes().containsKey("missing-kid"));

            // final step, verify if the user is not expired
            // this may happen if the user tokens have been issued for future use for example
            if (newUser.expired(config.getJWTOptions().getLeeway())) {
              handler.handle(Future.failedFuture("Used is expired."));
            } else {
              // basic validation passed, the token is not expired
              handler.handle(Future.succeededFuture(newUser));
            }
          });

        return;
      }

      // from this point, the only allowed sub type for credentials is OAuth2Credentials
      Oauth2Credentials oauth2Credentials = (Oauth2Credentials) credentials;
      oauth2Credentials.checkValid(config.getFlow());

      // the authInfo object does not contain a token, so rely on the
      // configured flow to retrieve a token for the user
      // depending on the flow type the authentication will behave in different ways
      final JsonObject params = new JsonObject();

      switch (config.getFlow()) {
        case AUTH_CODE:
          // code is always required. It's the code received on the web side
          params.put("code", oauth2Credentials.getCode());
          // must be identical to the redirect URI provided in the original link
          if (oauth2Credentials.getRedirectUri() != null) {
            params.put("redirect_uri", oauth2Credentials.getRedirectUri());
          }
          // the plaintext string that was previously hashed to create the code_challenge
          if (oauth2Credentials.getCodeVerifier() != null) {
            params.put("code_verifier", oauth2Credentials.getCodeVerifier());
          }
          break;

        case PASSWORD:
          params
            .put("username", oauth2Credentials.getUsername())
            .put("password", oauth2Credentials.getPassword());

          if (oauth2Credentials.getScopes() != null) {
            params.put("scope", String.join(config.getScopeSeparator(), oauth2Credentials.getScopes()));
          }
          break;

        case CLIENT:
          // applications may need an access token to act on behalf of themselves rather than a user.
          // in this case there are no parameters
          if (oauth2Credentials.getScopes() != null) {
            params.put("scope", String.join(config.getScopeSeparator(), oauth2Credentials.getScopes()));
          }
          break;

        case AUTH_JWT:
          params
            .put("assertion", jwt.sign(oauth2Credentials.getJwt(), config.getJWTOptions()));

          if (oauth2Credentials.getScopes() != null) {
            params.put("scope", String.join(config.getScopeSeparator(), oauth2Credentials.getScopes()));
          }
          break;

        case AAD_OBO:
          params
            .put("requested_token_use", "on_behalf_of")
            .put("assertion", oauth2Credentials.getAssertion());

          if (oauth2Credentials.getScopes() != null) {
            params.put("scope", String.join(config.getScopeSeparator(), oauth2Credentials.getScopes()));
          }
          break;

        default:
          handler.handle(Future.failedFuture("Current flow does not allow acquiring a token by the replay party"));
          return;
      }

      api.token(config.getFlow().getGrantType(), params, getToken -> {
        if (getToken.failed()) {
          handler.handle(Future.failedFuture(getToken.cause()));
        } else {

          // attempt to create a user from the json object
          final User newUser = createUser(getToken.result(), false);

          // final step, verify if the user is not expired
          // this may happen if the user tokens have been issued for future use for example
          if (newUser.expired(config.getJWTOptions().getLeeway())) {
            handler.handle(Future.failedFuture("Used is expired."));
          } else {
            // basic validation passed, the token is not expired
            handler.handle(Future.succeededFuture(newUser));
          }
        }
      });
    } catch (ClassCastException | CredentialValidationException e) {
      handler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public String authorizeURL(JsonObject params) {
    return api.authorizeURL(params);
  }

  @Override
  public OAuth2Auth refresh(User user, Handler<AsyncResult<User>> handler) {
    api.token(
      "refresh_token",
      new JsonObject()
        .put("refresh_token", user.principal().getString("refresh_token")),
      getToken -> {
        if (getToken.failed()) {
          handler.handle(Future.failedFuture(getToken.cause()));
        } else {
          // attempt to create a user from the json object
          final User newUser = createUser(getToken.result(), false);
          // final step, verify if the user is not expired
          // this may happen if the user tokens have been issued for future use for example
          if (newUser.expired(config.getJWTOptions().getLeeway())) {
            handler.handle(Future.failedFuture("Used is expired."));
          } else {
            // basic validation passed, the token is not expired
            handler.handle(Future.succeededFuture(newUser));
          }
        }
      });
    return this;
  }

  @Override
  public OAuth2Auth revoke(User user, String tokenType, Handler<AsyncResult<Void>> handler) {
    api.tokenRevocation(tokenType, user.principal().getString(tokenType), handler);
    return this;
  }

  @Override
  public OAuth2Auth userInfo(User user, Handler<AsyncResult<JsonObject>> handler) {
    api.userInfo(user.principal().getString("access_token"), jwt, userInfo -> {
      if (userInfo.succeeded()) {
        JsonObject json = userInfo.result();
        // validation (the subject must match)
        String userSub = user.principal().getString("sub", user.attributes().getString("sub"));
        String userInfoSub = json.getString("sub");
        if (userSub != null || userInfoSub != null) {
          if (userSub != null) {
            if (userInfoSub != null) {
              if (!userSub.equals(userInfoSub)) {
                handler.handle(Future.failedFuture("Used 'sub' does not match UserInfo 'sub'."));
                return;
              }
            }
          }
        }
        // copy basic properties to the attributes
        copyProperties(json, user.attributes(), true, "sub", "name", "email", "picture");
      }
      // complete
      handler.handle(userInfo);
    });
    return this;
  }

  @Override
  public String endSessionURL(User user, JsonObject params) {
    return api.endSessionURL(user.principal().getString("id_token"), params);
  }

  /**
   * Create a User object with some initial validations related to JWT.
   */
  private User createUser(JsonObject json, boolean skipMissingKeyNotify) {
    // update the principal
    final User user = User.create(json);
    final long now = System.currentTimeMillis() / 1000;

    // keep track of the missing kid if any, to debounce calls to
    // the missing key handler (at most 1 per missing key id)
    String missingKid = null;

    // compute the expires_at if any
    if (json.containsKey("expires_in")) {
      Long expiresIn;
      try {
        expiresIn = json.getLong("expires_in");
      } catch (ClassCastException e) {
        // for some reason someone decided to send a number as a String...
        expiresIn = Long.valueOf(json.getString("expires_in"));
      }
      // don't interfere with the principal object
      user.attributes()
        .put("iat", now)
        .put("exp", now + expiresIn);
    }

    // attempt to decode tokens if jwt keys are available
    if (!jwt.isUnsecure()) {
      if (json.containsKey("access_token")) {
        try {
          final JsonObject token = jwt.decode(json.getString("access_token"));
          // the OIDC validation will throw if the iss, aud do not match
          user.attributes()
            .put("accessToken", validToken(token, false));
          // copy the expiration check properties + sub to the root
          copyProperties(user.attributes().getJsonObject("accessToken"), user.attributes(), true, "exp", "iat", "nbf", "sub");
          // root claim meta data for JWT AuthZ
          user.attributes()
            .put("rootClaim", "accessToken");

        } catch (NoSuchKeyIdException e) {
          if (!skipMissingKeyNotify) {
            // tag the user attributes that we don't have the required key too
            user.attributes()
              .put("missing-kid", e.id());

            // save the missing kid
            missingKid = e.id();

            // the JWT store has no knowledge about the key id on this token
            // if the user has specified a handler for this situation then it
            // shall be executed, otherwise just log as a typical validation
            if (missingKeyHandler != null) {
              missingKeyHandler.handle(e.id());
            } else {
              LOG.trace("Cannot decode access token:", e);
            }
          }
        } catch (DecodeException | IllegalStateException e) {
          // explicitly catch and log. The exception here is a valid case
          // the reason is that it can be for several factors, such as bad token
          // or invalid JWT key setup, in that case we fall back to opaque token
          // which is the default operational mode for OAuth2.
          LOG.trace("Cannot decode access token:", e);
        }
      }

      if (json.containsKey("id_token")) {
        try {
          final JsonObject token = jwt.decode(json.getString("id_token"));
          // the OIDC validation will throw if the iss, aud do not match
          user.attributes()
            .put("idToken", validToken(token, true));
          // copy the userInfo basic properties to the root
          copyProperties(user.attributes().getJsonObject("idToken"), user.attributes(), false, "sub", "name", "email", "picture");
        } catch (NoSuchKeyIdException e) {
          if (!skipMissingKeyNotify) {
            // we haven't notified this id yet
            if (!e.id().equals(missingKid)) {
              // tag the user attributes that we don't have the required key too
              user.attributes()
                .put("missing-kid", e.id());

              // the JWT store has no knowledge about the key id on this token
              // if the user has specified a handler for this situation then it
              // shall be executed, otherwise just log as a typical validation
              if (missingKeyHandler != null) {
                missingKeyHandler.handle(e.id());
              } else {
                LOG.trace("Cannot decode access token:", e);
              }
            }
          }
        } catch (DecodeException | IllegalStateException e) {
          // explicitly catch and log. The exception here is a valid case
          // the reason is that it can be for several factors, such as bad token
          // or invalid JWT key setup, in that case we fall back to opaque token
          // which is the default operational mode for OAuth2.
          LOG.trace("Cannot decode id token:", e);
        }
      }
    }

    return user;
  }

  private JsonObject validToken(JsonObject token, boolean idToken) throws IllegalStateException {
    // the user object is a JWT so we should validate it as mandated by OIDC
    final JWTOptions jwtOptions = config.getJWTOptions();

    JsonArray target = null;

    // validate the audience
    if (token.containsKey("aud")) {
      try {
        if (token.getValue("aud") instanceof String) {
          target = new JsonArray().add(token.getValue("aud"));
        } else {
          target = token.getJsonArray("aud");
        }
      } catch (RuntimeException e) {
        throw new IllegalStateException("User audience isn't a JsonArray or String");
      }
    }

    if (target != null && target.size() > 0) {
      if (idToken || jwtOptions.getAudience() == null) {
        // https://openid.net/specs/openid-connect-core-1_0.html#  $3.1.3.7.
        // The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer
        // identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more
        // than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
        // or if it contains additional audiences not trusted by the Client.
        if (!target.contains(config.getClientId())) {
          throw new IllegalStateException("Invalid JWT audience. expected: " + config.getClientId());
        }
      } else {
        final List<String> aud = jwtOptions.getAudience();
        for (String el : aud) {
          if (!target.contains(el)) {
            throw new IllegalStateException("Invalid JWT audience. expected: " + el);
          }
        }
      }
    }

    // validate issuer
    if (jwtOptions.getIssuer() != null) {
      if (!jwtOptions.getIssuer().equals(token.getString("iss"))) {
        throw new IllegalStateException("Invalid JWT issuer");
      }
    }

    // validate authorised party
    if (idToken) {
      if (token.containsKey("azp")) {
        String clientId = config.getClientId();
        if (!clientId.equals(token.getString("azp"))) {
          throw new IllegalStateException("Invalid authorised party != config.clientID");
        }
        if (target != null && target.size() > 1) {
          // https://openid.net/specs/openid-connect-core-1_0.html#  $3.1.3.7.
          // If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
          if (!target.contains(token.getString("azp"))) {
            throw new IllegalStateException("ID Token with multiple audiences, doesn't contain azp Claim value");
          }
        }
      }
    }

    return token;
  }

  @Override
  @Deprecated
  public OAuth2Auth decodeToken(String token, Handler<AsyncResult<AccessToken>> handler) {
    try {
      JsonObject json = jwt.decode(token);
      handler.handle(Future.succeededFuture(createAccessToken(json)));
    } catch (RuntimeException e) {
      handler.handle(Future.failedFuture(e));
    }
    return this;
  }

  @Override
  @Deprecated
  public OAuth2Auth introspectToken(String token, String tokenType, Handler<AsyncResult<AccessToken>> handler) {
    api.tokenIntrospection(tokenType, token, introspection -> {
      if (introspection.failed()) {
        handler.handle(Future.failedFuture(introspection.cause()));
      } else {
        handler.handle(Future.succeededFuture(createAccessToken(introspection.result())));
      }
    });
    return this;
  }

  @Override
  @Deprecated
  public OAuth2FlowType getFlowType() {
    return config.getFlow();
  }

  @Override
  @Deprecated
  public OAuth2Auth rbacHandler(OAuth2RBAC rbac) {
    return this;
  }

  /**
   * Create a User object with some initial validations related to JWT.
   */
  @Deprecated
  private AccessToken createAccessToken(JsonObject json) {
    // update the principal
    final AccessToken user = new AccessTokenImpl(json, this);
    final long now = System.currentTimeMillis() / 1000;

    // compute the expires_at if any
    if (json.containsKey("expires_in")) {
      Long expiresIn;
      try {
        expiresIn = json.getLong("expires_in");
      } catch (ClassCastException e) {
        // for some reason someone decided to send a number as a String...
        expiresIn = Long.valueOf(json.getString("expires_in"));
      }
      // don't interfere with the principal object
      user.attributes()
        .put("iat", now)
        .put("exp", now + expiresIn);
    }

    // attempt to decode tokens
    if (json.getString("access_token") != null) {
      try {
        user.attributes()
          .put("accessToken", jwt.decode(json.getString("access_token")));

        // re-compute expires at if not present and access token has been successfully decoded from JWT
        if (!user.attributes().containsKey("exp")) {
          Long exp = user.attributes()
            .getJsonObject("accessToken").getLong("exp");

          if (exp != null) {
            user.attributes()
              .put("exp", exp);
          }
        }

        // root claim meta data for JWT AuthZ
        user.attributes()
          .put("rootClaim", "accessToken");

      } catch (NoSuchKeyIdException e) {
        // the JWT store has no knowledge about the key id on this token
        // if the user has specified a handler for this situation then it
        // shall be executed, otherwise just log as a typical validation
        if (missingKeyHandler != null) {
          missingKeyHandler.handle(e.id());
        } else {
          LOG.trace("Cannot decode access token:", e);
        }
      } catch (DecodeException | IllegalStateException e) {
        // explicitly catch and log as trace. exception here is a valid case
        // the reason is that it can be for several factors, such as bad token
        // or invalid JWT key setup, in that case we fall back to opaque token
        // which is the default operational mode for OAuth2.
        LOG.trace("Cannot decode access token:", e);
      }
    }

    if (json.getString("id_token") != null) {
      try {
        user.attributes()
          .put("idToken", jwt.decode(json.getString("id_token")));
      } catch (NoSuchKeyIdException e) {
        // the JWT store has no knowledge about the key id on this token
        // if the user has specified a handler for this situation then it
        // shall be executed, otherwise just log as a typical validation
        if (missingKeyHandler != null) {
          missingKeyHandler.handle(e.id());
        } else {
          LOG.trace("Cannot decode access token:", e);
        }
      } catch (DecodeException | IllegalStateException e) {
        // explicitly catch and log as trace. exception here is a valid case
        // the reason is that it can be for several factors, such as bad token
        // or invalid JWT key setup, in that case we fall back to opaque token
        // which is the default operational mode for OAuth2.
        LOG.trace("Cannot decode id token:", e);
      }
    }

    return user;
  }

  private static void copyProperties(JsonObject source, JsonObject target, boolean overwrite, String... keys) {
    if (source != null && target != null) {
      for (String key : keys) {
        if (source.containsKey(key)) {
          if (!target.containsKey(key) || overwrite) {
            target.put(key, source.getValue(key));
          }
        }
      }
    }
  }
}
