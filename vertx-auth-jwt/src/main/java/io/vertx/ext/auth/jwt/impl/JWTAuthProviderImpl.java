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
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Collections;

/**
 * @author Paulo Lopes
 */
public class JWTAuthProviderImpl implements JWTAuth {

  private static final JsonObject EMPTY_OBJECT = new JsonObject();
  private static final JsonArray EMPTY_ARRAY = new JsonArray();

  private final JWT jwt;

  private String permissionsClaimKey = "permissions";

  public JWTAuthProviderImpl(Vertx vertx, JksOptions keyStore) {
    try {
      if (keyStore != null) {
        final VertxInternal vertxInternal = (VertxInternal) vertx;
        final Buffer buffer;
        final String password = keyStore.getPassword();

        if (keyStore.getPath() != null && keyStore.getValue() == null) {
          keyStore.setValue(
              vertx.fileSystem().readFileBlocking(vertxInternal.resolveFile(keyStore.getPath()).getAbsolutePath()));
        }

        buffer = keyStore.getValue();

        KeyStore ks = KeyStore.getInstance("jceks");

        try (InputStream in = new ByteArrayInputStream(buffer.getBytes())) {
          ks.load(in, password != null ? password.toCharArray(): null);
        }

        this.jwt = new JWT(ks, password != null ? password.toCharArray(): null);
      } else {
        this.jwt = new JWT(null, null);
      }

    } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public JWTAuth setPermissionsClaimKey(String name) {
    this.permissionsClaimKey = name;
    return this;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    try {
      final JsonObject payload = jwt.decode(authInfo.getString("jwt"));

      final JsonObject options = authInfo.getJsonObject("options", EMPTY_OBJECT);

      // All dates in JWT are of type NumericDate
      // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
      // the specified UTC date/time, ignoring leap seconds
      final long now = System.currentTimeMillis() / 1000;

      if (payload.containsKey("exp") && !options.getBoolean("ignoreExpiration", false)) {
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

      if (options.containsKey("audience")) {
        JsonArray audiences = options.getJsonArray("audience", EMPTY_ARRAY);
        JsonArray target = payload.getJsonArray("aud", EMPTY_ARRAY);

        if (Collections.disjoint(audiences.getList(), target.getList())) {
          resultHandler.handle(Future.failedFuture("Invalid JWT audient. expected: " + audiences.encode()));
          return;
        }
      }

      if (options.containsKey("issuer")) {
        if (!options.getString("issuer").equals(payload.getString("iss"))) {
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
    final JsonObject jsonOptions = options.toJSON();

    // we do some "enhancement" of the claims to support roles and permissions
    if (jsonOptions.containsKey("permissions") && !claims.containsKey(permissionsClaimKey)) {
      claims.put(permissionsClaimKey, jsonOptions.getJsonArray("permissions"));
    }

    return jwt.sign(claims, options.toJSON());
  }
}
