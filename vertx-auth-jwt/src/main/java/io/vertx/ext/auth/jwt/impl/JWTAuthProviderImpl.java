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

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.file.FileSystemException;
import io.vertx.core.internal.logging.Logger;
import io.vertx.core.internal.logging.LoggerFactory;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jose.JWTOptions;
import io.vertx.ext.auth.jose.KeyStoreOptions;
import io.vertx.ext.auth.jose.PubSecKeyOptions;
import io.vertx.ext.auth.user.User;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.impl.jose.JWK;
import io.vertx.ext.auth.impl.jose.JWT;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author Paulo Lopes
 */
public class JWTAuthProviderImpl implements JWTAuth {

  private static final Logger LOG = LoggerFactory.getLogger(JWTAuthProviderImpl.class);

  private static final JsonArray EMPTY_ARRAY = new JsonArray(Collections.emptyList());

  private final JWT jwt = new JWT();

  private final JWTOptions jwtOptions;

  public JWTAuthProviderImpl(Vertx vertx, JWTAuthOptions config) {
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
          try {
            jwt.addJWK(new JWK(jwk));
          } catch (Exception e) {
            LOG.warn("Unsupported JWK", e);
          }
        }
      }

    } catch (KeyStoreException | IOException | FileSystemException | CertificateException | NoSuchAlgorithmException |
             NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final TokenCredentials authInfo;
    try {
      // cast
      try {
        authInfo = (TokenCredentials) credentials;
      } catch (ClassCastException e) {
        throw new CredentialValidationException("Invalid credentials type", e);
      }
      // check
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    final JsonObject payload;
    try {
      payload = jwt.decode(authInfo.getToken());
    } catch (SignatureException | RuntimeException e) {
      return Future.failedFuture(e);
    }

    if (jwtOptions.getAudience() != null) {
      JsonArray target;
      if (payload.getValue("aud") instanceof String) {
        target = new JsonArray().add(payload.getValue("aud", ""));
      } else {
        target = payload.getJsonArray("aud", EMPTY_ARRAY);
      }

      if (Collections.disjoint(jwtOptions.getAudience(), target.getList())) {
        return Future.failedFuture("Invalid JWT audience. expected: " + Json.encode(jwtOptions.getAudience()));
      }
    }

    if (jwtOptions.getIssuer() != null) {
      if (!jwtOptions.getIssuer().equals(payload.getString("iss"))) {
        return Future.failedFuture("Invalid JWT issuer");
      }
    }

    final User user = createUser(authInfo.getToken(), payload);

    if (user.expired(jwtOptions.getLeeway())) {
      if (!jwtOptions.isIgnoreExpiration()) {
        return Future.failedFuture("Invalid JWT token: token expired.");
      }
    }

    return Future.succeededFuture(user);
  }

  @Override
  public String generateToken(JsonObject claims, final JWTOptions options) {
    return jwt.sign(claims, options);
  }

  @Override
  public String generateToken(JsonObject claims) {
    return generateToken(claims, jwtOptions);
  }

  private static final Collection<String> SPECIAL_KEYS = Arrays.asList("access_token", "exp", "iat", "nbf");

  private User createUser(String accessToken, JsonObject jwtToken) {
    User result = User.fromToken(accessToken);

    if (jwtToken.containsKey("amr")) {
      // metadata "amr"
      result.principal().put("amr", jwtToken.getValue("amr"));
    }

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
}
