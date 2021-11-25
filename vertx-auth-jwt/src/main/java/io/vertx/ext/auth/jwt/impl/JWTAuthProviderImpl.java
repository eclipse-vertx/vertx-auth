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
package io.vertx.ext.auth.jwt.impl;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystemException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author Paulo Lopes
 */
public class JWTAuthProviderImpl implements JWTAuth {

  private static final JsonArray EMPTY_ARRAY = new JsonArray();

  private final JWT jwt = new JWT();

  private final String permissionsClaimKey;
  private final JWTOptions jwtOptions;

  public JWTAuthProviderImpl(Vertx vertx, JWTAuthOptions config) {
    this.permissionsClaimKey = config.getPermissionsClaimKey();
    this.jwtOptions = config.getJWTOptions();
    // set the nonce algorithm
    jwt.nonceAlgorithm(jwtOptions.getNonceAlgorithm());

    final KeyStoreOptions keyStore = config.getKeyStore();

    // attempt to load a Key file
    try {
      if (keyStore != null) {
        final KeyStore ks;
        if (keyStore.getProvider() == null) {
          ks = KeyStore.getInstance(keyStore.getType());
        } else {
          ks = KeyStore.getInstance(keyStore.getType(), keyStore.getProvider());
        }

        // synchronize on the class to avoid the case where multiple file accesses will overlap
        synchronized (JWTAuthProviderImpl.class) {
          String path = keyStore.getPath();
          if (path != null) {
            final Buffer keystore = vertx.fileSystem().readFileBlocking(keyStore.getPath());

            try (InputStream in = new ByteArrayInputStream(keystore.getBytes())) {
              ks.load(in, keyStore.getPassword().toCharArray());
            }
          } else {
            ks.load(null, keyStore.getPassword().toCharArray());
          }
        }
        // load all available keys in the keystore
        for (JWK key : JWK.load(ks, keyStore.getPassword(), keyStore.getPasswordProtection())) {
          jwt.addJWK(key);
        }
      }
      // attempt to load pem keys
      final List<PubSecKeyOptions> keys = config.getPubSecKeys();

      if (keys != null) {
        for (PubSecKeyOptions pubSecKey : config.getPubSecKeys()) {
          jwt.addJWK(new JWK(pubSecKey));
        }
      }

      // attempt to load jwks
      final List<JsonObject> jwks = config.getJwks();

      if (jwks != null) {
        for (JsonObject jwk : jwks) {
          this.jwt.addJWK(new JWK(jwk));
        }
      }

    } catch (KeyStoreException | IOException | FileSystemException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    authenticate(new TokenCredentials(authInfo.getString("token")), resultHandler);
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {
    try {
      // cast
      TokenCredentials authInfo = (TokenCredentials) credentials;
      // check
      authInfo.checkValid(null);

      final JsonObject payload = jwt.decode(authInfo.getToken());

      if (jwtOptions.getAudience() != null) {
        JsonArray target;
        if (payload.getValue("aud") instanceof String) {
          target = new JsonArray().add(payload.getValue("aud", ""));
        } else {
          target = payload.getJsonArray("aud", EMPTY_ARRAY);
        }

        if (Collections.disjoint(jwtOptions.getAudience(), target.getList())) {
          resultHandler.handle(Future.failedFuture("Invalid JWT audience. expected: " + Json.encode(jwtOptions.getAudience())));
          return;
        }
      }

      if (jwtOptions.getIssuer() != null) {
        if (!jwtOptions.getIssuer().equals(payload.getString("iss"))) {
          resultHandler.handle(Future.failedFuture("Invalid JWT issuer"));
          return;
        }
      }

      final User user = createUser(authInfo.getToken(), payload, permissionsClaimKey);

      if (user.expired(jwtOptions.getLeeway())) {
        if (!jwtOptions.isIgnoreExpiration()) {
          resultHandler.handle(Future.failedFuture("Invalid JWT token: token expired."));
          return;
        }
      }

      resultHandler.handle(Future.succeededFuture(user));

    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public String generateToken(JsonObject claims, final JWTOptions options) {
    final JsonObject _claims = claims.copy();

    // we do some "enhancement" of the claims to support roles and permissions
    if (options.getPermissions() != null && !_claims.containsKey(permissionsClaimKey)) {
      _claims.put(permissionsClaimKey, new JsonArray(options.getPermissions()));
    }

    return jwt.sign(_claims, options);
  }

  @Override
  public String generateToken(JsonObject claims) {
    return generateToken(claims, jwtOptions);
  }

  private static JsonArray getJsonPermissions(JsonObject jwtToken, String permissionsClaimKey) {
    if (permissionsClaimKey.contains("/")) {
      return getNestedJsonValue(jwtToken, permissionsClaimKey);
    }
    return jwtToken.getJsonArray(permissionsClaimKey, null);
  }

  private static final Collection<String> SPECIAL_KEYS = Arrays.asList("access_token", "exp", "iat", "nbf");

  /**
   * @deprecated This method is deprecated as it introduces an exception to the internal representation of {@link User}
   * object data.
   * In the future a simple call to User.create() should be used
   */
  @Deprecated
  private User createUser(String accessToken, JsonObject jwtToken, String permissionsClaimKey) {
    User result = User.fromToken(accessToken);

    // update the attributes
    result.attributes()
      .put("accessToken", jwtToken);

    // copy the expiration check properties + sub to the attributes root
    copyProperties(jwtToken, result.attributes(), "exp", "iat", "nbf", "sub");
    // as the token is immutable, the decoded values will be added to the principal
    // with the exception of the above ones
    for (String key : jwtToken.fieldNames()) {
      if (!SPECIAL_KEYS.contains(key)) {
        result.principal().put(key, jwtToken.getValue(key));
      }
    }

    // root claim meta data for JWT AuthZ
    result.attributes()
      .put("rootClaim", "accessToken");

    JsonArray jsonPermissions = getJsonPermissions(jwtToken, permissionsClaimKey);
    if (jsonPermissions != null) {
      for (Object item : jsonPermissions) {
        if (item instanceof String) {
          String permission = (String) item;
          result.authorizations().add("jwt-authentication", PermissionBasedAuthorization.create(permission));
        }
      }
    }
    return result;
  }

  private static void copyProperties(JsonObject source, JsonObject target, String... keys) {
    if (source != null && target != null) {
      for (String key : keys) {
        if (source.containsKey(key) && !target.containsKey(key)) {
          target.put(key, source.getValue(key));
        }
      }
    }
  }

  private static @Nullable JsonArray getNestedJsonValue(JsonObject jwtToken, String permissionsClaimKey) {
    String[] keys = permissionsClaimKey.split("/");
    JsonObject obj = null;
    for (int i = 0; i < keys.length; i++) {
      if (i == 0) {
        obj = jwtToken.getJsonObject(keys[i]);
      } else if (i == keys.length - 1) {
        if (obj != null) {
          return obj.getJsonArray(keys[i]);
        }
      } else {
        if (obj != null) {
          obj = obj.getJsonObject(keys[i]);
        }
      }
    }
    return null;
  }
}
