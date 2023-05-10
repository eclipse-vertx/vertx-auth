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

import io.vertx.core.*;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
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

import java.security.SignatureException;
import java.util.Collections;

import static java.lang.Math.max;

/**
 * @author Paulo Lopes
 */
public class OAuth2AuthProviderImpl implements OAuth2Auth, Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthProviderImpl.class);

  private final Vertx vertx;
  private final Context context;

  private final OAuth2Options config;
  private final OAuth2API api;

  // avoid caching, as it may swap,
  // old references are still valid though
  private volatile JWT jwt = new JWT();
  private volatile long updateTimerId = -1;
  private Handler<String> missingKeyHandler;

  public OAuth2AuthProviderImpl(Vertx vertx, OAuth2Options config) {
    this.vertx = vertx;
    this.context = vertx.getOrCreateContext();
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
        try {
          jwt.addJWK(new JWK(pubSecKey));
        } catch (RuntimeException e) {
          LOG.warn("Unsupported JWK", e);
        }
      }
    }

    if (config.getJwks() != null) {
      for (JsonObject jwk : config.getJwks()) {
        try {
          jwt.addJWK(new JWK(jwk));
        } catch (RuntimeException e) {
          LOG.warn("Unsupported JWK", e);
        }
      }
    }
  }

  @Override
  public void close() {
    synchronized (this) {
      if (updateTimerId != -1) {
        // cancel any running timer to avoid multiple updates
        // it is not important if the timer isn't active anymore

        // this could happen if both the user triggers the update and
        // there's a timer already in progress
        vertx.cancelTimer(updateTimerId);
        ((VertxInternal) vertx).removeCloseHook(this);
        updateTimerId = -1;
      }
      // clear the JWT object reference too
      jwt = null;
    }
  }

  @Override
  public Future<Void> jWKSet() {
    return api.jwkSet()
      .compose(json -> {
        // enforce a lock to ensure state isn't corrupted
        synchronized (OAuth2AuthProviderImpl.this) {
          if (updateTimerId != -1) {
            // cancel any running timer to avoid multiple updates
            // it is not important if the timer isn't active anymore

            // this could happen if both the user triggers the update and
            // there's a timer already in progress
            vertx.cancelTimer(updateTimerId);
            ((VertxInternal) vertx).removeCloseHook(this);
          }

          JWT jwt = new JWT()
            // set the nonce algorithm
            .nonceAlgorithm(config.getJWTOptions().getNonceAlgorithm());

          JsonArray keys = json.getJsonArray("keys");
          for (Object key : keys) {
            try {
              jwt.addJWK(new JWK((JsonObject) key));
            } catch (Exception e) {
              LOG.warn("Unsupported JWK", e);
            }
          }
          // swap
          this.jwt = jwt;

          // ensure that leeway is never negative
          int leeway = max(0, config.getJWTOptions().getLeeway());
          // delay is in ms, while cache max age is sec
          final long delay = json.getLong("maxAge", config.getJwkMaxAgeInSeconds()) * 1000 - leeway;
          // salesforce (for example) sometimes disables the max-age as setting it to 0
          // for these cases we just cancel
          if (delay > 0) {
            this.updateTimerId = vertx.setPeriodic(delay, t ->
              jWKSet()
                .onFailure(err -> LOG.warn("Failed to auto-update JWK Set", err)));
            // ensure we get a clean exit
            ((VertxInternal) vertx).addCloseHook(this);
          } else {
            updateTimerId = -1;
          }
        }
        return Future.succeededFuture();
      });
  }

  @Override
  public OAuth2Auth missingKeyHandler(Handler<String> handler) {
    this.missingKeyHandler = handler;
    return this;
  }

  public OAuth2Options getConfig() {
    return config;
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
  public Future<User> authenticate(Credentials credentials) {
    try {
      // adapt credential type to be always the expected one
      if (credentials instanceof UsernamePasswordCredentials) {
        UsernamePasswordCredentials usernamePasswordCredentials = (UsernamePasswordCredentials) credentials;
        usernamePasswordCredentials.checkValid(null);

        Oauth2Credentials cred = new Oauth2Credentials()
          .setUsername(usernamePasswordCredentials.getUsername())
          .setPassword(usernamePasswordCredentials.getPassword())
          .setFlow(OAuth2FlowType.PASSWORD);

        return authenticate(cred);
      }

      // if the authInfo object already contains a token validate it to confirm that it
      // can be reused, otherwise, based on the configured flow, request a new token
      // from the authority provider

      if (credentials instanceof TokenCredentials) {
        // authInfo contains a non null token
        TokenCredentials tokenCredentials = (TokenCredentials) credentials;
        tokenCredentials.checkValid(null);

        // this validation can be done in 2 different ways:
        // 1) the token is a JWT and in this case if the provider is OpenId Compliant the token can be verified locally
        // 2) the token is an opaque string, and we need to introspect it

        // if the JWT library is working in unsecure mode, local validation is not to be trusted

        final User user = createUser(new JsonObject().put("access_token", tokenCredentials.getToken()), false);

        if (!user.principal().getBoolean("opaque", false)) {
          if (user.attributes().containsKey("accessToken")) {
            final JWTOptions jwtOptions = config.getJWTOptions();
            // a valid JWT token should have the access token value decoded
            // the token might be valid, but expired
            if (!user.expired(jwtOptions.getLeeway())) {
              // basic validation passed, the token is not expired
              return Future.succeededFuture(user);
            }
          }
        }

        // the token is not in JWT format or this auth provider is not configured for secure JWTs
        // in this case we must rely on token introspection in order to know more about its state
        // attempt to create a token object from the given string representation

        // Not all providers support this so we need to check if the call is possible
        if (config.getIntrospectionPath() == null) {
          // this provider doesn't allow introspection, this means we are not able to perform
          // any authentication, unless the userinfo endpoint is available. In this case, we shall
          // call that endpoint and the result should be handled as a decoded id_token

          if (config.getUserInfoPath() == null) {
            if (user.attributes().containsKey("missing-kid")) {
              return Future.failedFuture(new NoSuchKeyIdException(user.attributes().getString("missing-kid")));
            } else {
              return Future.failedFuture("Can't authenticate access_token: Provider doesn't support token introspection or userinfo");
            }
          }

          // perform the introspection
          return api
            .userInfo(tokenCredentials.getToken(), jwt)
            .compose(json -> {
              // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations may not return this)
              if (json.containsKey("active") && !json.getBoolean("active", false)) {
                return Future.failedFuture("Inactive Token");
              }

              // attempt to create a user from the json object
              final User newUser = createUser(
                new JsonObject()
                  .put("access_token", tokenCredentials.getToken()),
                user.attributes().containsKey("missing-kid"));

              // replace the user info with the user attributes
              newUser.attributes().put("idToken", json);

              // copy the userInfo basic properties to the root
              copyProperties(json, user.attributes(), false, "sub", "name", "email", "picture");
              // copy amr to the principal
              copyProperties(json, user.principal(), true, "amr");

              // final step, verify if the user is not expired
              // this may happen if the user tokens have been issued for future use for example
              if (newUser.expired(config.getJWTOptions().getLeeway())) {
                return Future.failedFuture("User token is expired.");
              } else {
                // basic validation passed, the token is not expired
                return Future.succeededFuture(newUser);
              }
            });
        }

        // perform the introspection
        return api
          .tokenIntrospection("access_token", tokenCredentials.getToken())
          .compose(json -> {
            // RFC7662 dictates that there is a boolean active field (however tokeninfo implementations may not return this)
            if (json.containsKey("active") && !json.getBoolean("active", false)) {
              return Future.failedFuture("Inactive Token");
            }

            // OPTIONALS

            // validate client id
            if (json.containsKey("client_id")) {
              // response included a client id. Match against config client id
              String clientId = config.getClientId();
              if (clientId != null && !clientId.equals(json.getString("client_id"))) {
                // Client identifier for the OAuth 2.0 client that requested this token.
                LOG.info("Introspected client_id doesn't match configured client_id");
                if (LOG.isDebugEnabled()) {
                  LOG.debug(String.format("Introspected client_id: %s", clientId));
                  LOG.debug(String.format("Configured client_id: %s", json.getString("client_id")));
                }
              }
            }

            // attempt to create a user from the json object
            final User newUser = createUser(
              json,
              user.attributes().containsKey("missing-kid"));

            // final step, verify if the user is not expired
            // this may happen if the user tokens have been issued for future use for example
            if (newUser.expired(config.getJWTOptions().getLeeway())) {
              return Future.failedFuture("User token is expired.");
            } else {
              // basic validation passed, the token is not expired
              return Future.succeededFuture(newUser);
            }
          });
      }

      // from this point, the only allowed subtype for credentials is OAuth2Credentials
      Oauth2Credentials oauth2Credentials = (Oauth2Credentials) credentials;

      // the authInfo object does not contain a token, so rely on the
      // configured flow to retrieve a token for the user
      // depending on the flow type the authentication will behave in different ways
      oauth2Credentials.checkValid(config.getSupportedGrantTypes());
      final OAuth2FlowType flow = oauth2Credentials.getFlow();

      if (config.getSupportedGrantTypes() != null && !config.getSupportedGrantTypes().isEmpty() &&
        !config.getSupportedGrantTypes().contains(flow.getGrantType())) {
        return Future.failedFuture("Provided flow is not supported by provider");
      }

      final JsonObject params = new JsonObject();

      switch (flow) {
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
            .put("assertion", jwt.sign(oauth2Credentials.getJwt().copy(), config.getJWTOptions()));

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
          return Future.failedFuture("Current flow does not allow acquiring a token by the replay party");
      }

      return api.token(flow.getGrantType(), params)
        .compose(json -> {
          // attempt to create a user from the json object
          final User newUser = createUser(
            json,
            false);

          // final step, verify if the user is not expired
          // this may happen if the user tokens have been issued for future use for example
          if (newUser.expired(config.getJWTOptions().getLeeway())) {
            return Future.failedFuture("User token is expired.");
          } else {
            // basic validation passed, the token is not expired
            return Future.succeededFuture(newUser);
          }
        });
    } catch (ClassCastException | CredentialValidationException e) {
      return Future.failedFuture(e);
    }
  }

  @Override
  public String authorizeURL(OAuth2AuthorizationURL url) {
    return api.authorizeURL(url);
  }

  @Override
  public Future<User> refresh(User user) {

    if (user.principal().getString("refresh_token") == null || user.principal().getString("refresh_token").isEmpty()) {
      return Future.failedFuture(new IllegalStateException("refresh_token is null or empty"));
    }

    return api.token(
        "refresh_token",
        new JsonObject()
          .put("refresh_token", user.principal().getString("refresh_token")))
      .compose(json -> {
        // attempt to create a user from the json object
        final User newUser = createUser(
          json,
          false);
        // final step, verify if the user is not expired
        // this may happen if the user tokens have been issued for future use for example
        if (newUser.expired(config.getJWTOptions().getLeeway())) {
          return Future.failedFuture("User token is expired.");
        } else {
          // basic validation passed, the token is not expired
          return Future.succeededFuture(newUser);
        }
      });
  }

  @Override
  public Future<Void> revoke(User user, String tokenType) {
    return api.tokenRevocation(tokenType, user.principal().getString(tokenType));
  }

  @Override
  public Future<JsonObject> userInfo(User user) {
    return api.userInfo(user.principal().getString("access_token"), jwt)
      .compose(json -> {
        // validation (the subject must match)
        String userSub = user.principal().getString("sub", user.attributes().getString("sub"));
        String userInfoSub = json.getString("sub");
        if (userSub != null || userInfoSub != null) {
          if (userSub != null) {
            if (userInfoSub != null) {
              if (!userSub.equals(userInfoSub)) {
                return Future.failedFuture("Used 'sub' does not match UserInfo 'sub'.");
              }
            }
          }
        }

        // copy basic properties to the attributes
        copyProperties(json, user.attributes(), true);

        // final step, verify if the user is not expired
        // this may happen if the user tokens have been issued for future use for example
        if (user.expired(config.getJWTOptions().getLeeway())) {
          return Future.failedFuture("User token is expired.");
        } else {
          // basic validation passed, the user token is not expired
          return Future.succeededFuture(json);
        }
      });
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

        } catch (DecodeException | IllegalArgumentException e) {
          // This set of exceptions here are a valid cases
          // the reason is that it can be for several factors,
          // such as bad token or invalid JWT key setup, in
          // that case we fall back to opaque token which is
          // the default operational mode for OAuth2.
          user.principal()
            .put("opaque", true);
        } catch (NoSuchKeyIdException e) {
          user.principal()
            .put("opaque", true);

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
              context.runOnContext(v -> missingKeyHandler.handle(e.id()));
            }
          }
        } catch (SignatureException | IllegalStateException e) {
          // The token is a JWT but validation failed
          LOG.trace("Invalid JWT access_token:", e);
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
          // copy amr to the principal
          copyProperties(user.attributes().getJsonObject("idToken"), user.principal(), true, "amr");
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
                context.runOnContext(v -> missingKeyHandler.handle(e.id()));
              }
            }
          }
        } catch (SignatureException | DecodeException | IllegalArgumentException | IllegalStateException e) {
          // explicitly catch and log. The exception here is a valid case
          // the reason is that it can be for several factors, such as bad token
          // or invalid JWT key setup, in that case we can't decode the token.
          LOG.trace("Invalid JWT id_token:", e);
        }
      }
    } else {
      user.principal()
        .put("opaque", true);
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
        if (Collections.disjoint(jwtOptions.getAudience(), target.getList())) {
          throw new IllegalStateException("Invalid JWT audience. expected: " + Json.encode(jwtOptions.getAudience()));
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

  private static void copyProperties(JsonObject source, JsonObject target, boolean overwrite, String... keys) {
    if (source != null && target != null) {
      if (keys.length == 0) {
        for (String key : source.fieldNames()) {
          if (!target.containsKey(key) || overwrite) {
            target.put(key, source.getValue(key));
          }
        }
      } else {
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

  @Override
  public void close(Promise<Void> onClose) {
    close();
    onClose.complete();
  }
}
