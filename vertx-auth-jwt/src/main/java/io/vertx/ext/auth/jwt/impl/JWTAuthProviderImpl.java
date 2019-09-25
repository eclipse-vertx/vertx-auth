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

import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystemException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
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

  private final Vertx vertx;
  private volatile JWTState state;

  public JWTAuthProviderImpl(Vertx vertx) {
    this.vertx = vertx;
    this.state = new JWTState();
  }

  @Override
  public synchronized JWTAuth update(JWTAuthOptions config) {
    state = new JWTState(vertx, config);
    return this;
  }

  @Override
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    // lock to the current state, if it gets replaced in the meanwhile
    // we always refer to a correct state
    final JWTState state = this.state;

    // shorthand
    final JWT jwt = state.jwt;
    final JWTOptions options = state.jwtOptions;
    final String permissionsClaimKey = state.permissionsClaimKey;

    try {
      final JsonObject payload = jwt.decode(authInfo.getString("jwt"));

      if (jwt.isExpired(payload, options)) {
        resultHandler.handle(Future.failedFuture("Expired JWT token."));
        return;
      }

      final List<String> aud = options.getAudience();

      if (aud != null) {
        JsonArray target;
        if (payload.getValue("aud") instanceof String) {
          target = new JsonArray().add(payload.getValue("aud", ""));
        } else {
          target = payload.getJsonArray("aud", EMPTY_ARRAY);
        }

        if (Collections.disjoint(aud, target.getList())) {
          resultHandler.handle(Future.failedFuture("Invalid JWT audience. expected: " + Json.encode(aud)));
          return;
        }
      }

      if (options.getIssuer() != null) {
        if (!options.getIssuer().equals(payload.getString("iss"))) {
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
  public String generateToken(JsonObject claims, JWTOptions options) {
    // lock to the current state, if it gets replaced in the meanwhile
    // we always refer to a correct state
    final JWTState state = this.state;

    // shorthand
    final JWT jwt = state.jwt;
    final String permissionsClaimKey = state.permissionsClaimKey;
    if (options == null) {
      // use the config defaults
      options = state.jwtOptions;
    }

    // we do some "enhancement" of the claims to support roles and permissions
    if (options.getPermissions() != null && !claims.containsKey(permissionsClaimKey)) {
      // a new claim will be added so we must copy to avoid modifying the original object
      claims = claims.copy();
      claims.put(permissionsClaimKey, new JsonArray(options.getPermissions()));
    }

    return jwt.sign(claims, options);
  }

  private static class JWTState {

    private final JWT jwt;
    private final String permissionsClaimKey;
    private final JWTOptions jwtOptions;

    JWTState() {
      jwt = new JWT();
      permissionsClaimKey = null;
      jwtOptions = new JWTOptions();
    }

    JWTState(Vertx vertx, JWTAuthOptions config) {
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
              jwt.addJWK(JWK.from(pubSecKey));
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
  }
}
