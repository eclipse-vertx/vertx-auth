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
import io.vertx.ext.auth.User;
import io.vertx.ext.jwt.*;

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
  private final String issuer;
  private final List<String> audience;
  private final boolean ignoreExpiration;

  public JWTAuthProviderImpl(Vertx vertx, JWTAuthOptions config) {
    this.permissionsClaimKey = config.getPermissionsClaimKey();
    this.issuer = config.getIssuer();
    this.audience = config.getAudience();
    this.ignoreExpiration = config.isIgnoreExpiration();

    final JWTKeyStoreOptions keyStore = config.getKeyStore();

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
        // in the case of not having a key store we will try to load a public key in pem format
        // this is how keycloak works as an example.
        this.jwt = new JWT();

        if (config.containsKey("public-key")) {
          this.jwt.addPublicKey("RS256", config.getPublicKey());

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

      // All dates in JWT are of type NumericDate
      // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
      // the specified UTC date/time, ignoring leap seconds
      final long now = System.currentTimeMillis() / 1000;

      if (payload.containsKey("exp") && !ignoreExpiration) {
        if (now >= payload.getLong("exp")) {
          resultHandler.handle(Future.failedFuture("Expired JWT token: exp <= now"));
          return;
        }
      }

      if (payload.containsKey("iat")) {
        Long iat = payload.getLong("iat");
        // issue at must be in the past
        if (iat > now) {
          resultHandler.handle(Future.failedFuture("Invalid JWT token: iat > now"));
          return;
        }
      }

      if (payload.containsKey("nbf")) {
        Long nbf = payload.getLong("nbf");
        // not before must be after now
        if (nbf > now) {
          resultHandler.handle(Future.failedFuture("Invalid JWT token: nbf > now"));
          return;
        }
      }

      if (audience != null) {
        JsonArray target;
        if (payload.getValue("aud") instanceof String) {
          target = new JsonArray().add(payload.getValue("aud", ""));
        } else {
          target = payload.getJsonArray("aud", EMPTY_ARRAY);
        }

        if (Collections.disjoint(audience, target.getList())) {
          resultHandler.handle(Future.failedFuture("Invalid JWT audient. expected: " + Json.encode(audience)));
          return;
        }
      }

      if (issuer != null) {
        if (!issuer.equals(payload.getString("iss"))) {
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
    final JsonObject jsonOptions = options.toJson();
    final JsonObject _claims = claims.copy();

    // we do some "enhancement" of the claims to support roles and permissions
    if (jsonOptions.containsKey("permissions") && !_claims.containsKey(permissionsClaimKey)) {
      _claims.put(permissionsClaimKey, jsonOptions.getJsonArray("permissions"));
    }

    return jwt.sign(_claims, jsonOptions);
  }
}
