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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystemException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.SecretOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.jwt.JWK;
import io.vertx.ext.jwt.JWT;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

/**
 * @author Paulo Lopes
 */
public class JWTAuthProviderImpl implements JWTAuth {

  private static final JsonArray EMPTY_ARRAY = new JsonArray();

  private final JWT jwt;

  private final String permissionsClaimKey;
  private final JWTOptions jwtOptions;

  public JWTAuthProviderImpl(Vertx vertx, JWTAuthOptions config) {
    this.permissionsClaimKey = config.getPermissionsClaimKey();
    this.jwtOptions = config.getJWTOptions();

    final KeyStoreOptions keyStore = config.getKeyStore();

    // attempt to load a Key file
    try {
      if (keyStore != null) {
        KeyStore ks = KeyStore.getInstance(keyStore.getType());

        // synchronize on the class to avoid the case where multiple file accesses will overlap
        synchronized (JWTAuthProviderImpl.class) {
          final Buffer keystore = vertx.fileSystem().readFileBlocking(keyStore.getPath());

          try (InputStream in = new ByteArrayInputStream(keystore.getBytes())) {
            ks.load(in, keyStore.getPassword().toCharArray());
          }
        }

        this.jwt = new JWT(ks, keyStore.getPassword().toCharArray());
      } else {
        // no key file attempt to load pem keys
        this.jwt = new JWT();

        final List<PubSecKeyOptions> keys = config.getPubSecKeys();

        if (keys != null) {
          for (PubSecKeyOptions pubSecKey : config.getPubSecKeys()) {
            if (pubSecKey.isSymmetric()) {
              jwt.addJWK(new JWK(pubSecKey.getAlgorithm(), pubSecKey.getPublicKey()));
            } else {
              jwt.addJWK(new JWK(pubSecKey.getAlgorithm(), pubSecKey.isCertificate(), pubSecKey.getPublicKey(), pubSecKey.getSecretKey()));
            }
          }
        }

        // TODO: remove once the deprecation ends!
        final List<SecretOptions> secrets = config.getSecrets();

        if (secrets != null) {
          for (SecretOptions secret: secrets) {
            this.jwt.addSecret(secret.getType(), secret.getSecret());
          }
        }

        final List<JsonObject> jwks = config.getJwks();

        if (jwks != null) {
          for (JsonObject jwk : jwks) {
            this.jwt.addJWK(new JWK(jwk));
          }
        }
      }

    } catch (KeyStoreException | IOException | FileSystemException | CertificateException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    try {
      final JsonObject payload = jwt.decode(authInfo.getString("jwt"));

      if (jwt.isExpired(payload, jwtOptions)) {
        resultHandler.handle(Future.failedFuture("Expired JWT token."));
        return;
      }

      if (jwtOptions.getAudience() != null) {
        JsonArray target;
        if (payload.getValue("aud") instanceof String) {
          target = new JsonArray().add(payload.getValue("aud", ""));
        } else {
          target = payload.getJsonArray("aud", EMPTY_ARRAY);
        }

        if (Collections.disjoint(jwtOptions.getAudience(), target.getList())) {
          resultHandler.handle(Future.failedFuture("Invalid JWT audient. expected: " + Json.encode(jwtOptions.getAudience())));
          return;
        }
      }

      if (jwtOptions.getIssuer() != null) {
        if (!jwtOptions.getIssuer().equals(payload.getString("iss"))) {
          resultHandler.handle(Future.failedFuture("Invalid JWT issuer"));
          return;
        }
      }

      resultHandler.handle(Future.succeededFuture(new JWTUser(payload, permissionsClaimKey)));

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
}
