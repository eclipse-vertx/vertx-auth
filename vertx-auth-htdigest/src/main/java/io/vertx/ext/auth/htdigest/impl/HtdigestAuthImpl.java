/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.htdigest.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.htdigest.HtdigestAuth;
import io.vertx.ext.auth.htdigest.HtdigestCredentials;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static io.vertx.ext.auth.impl.Codec.base16Encode;

/**
 * An implementation of {@link HtdigestAuth}
 *
 * @author Paulo Lopes
 */
public class HtdigestAuthImpl implements HtdigestAuth {

  private static final MessageDigest MD5;

  private static class Digest {
    final String username;
    final String realm;
    final String password;

    Digest(String username, String realm, String password) {

      this.username = username;
      this.realm = realm;
      this.password = password;
    }
  }

  static {
    try {
      MD5 = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private final Map<String, Digest> htdigest = new HashMap<>();
  private final String realm;

  /**
   * Creates a new instance
   */
  public HtdigestAuthImpl(Vertx vertx, String htdigestFile) {
    String realm = null;
    // load the file into memory
    for (String line : vertx.fileSystem().readFileBlocking(htdigestFile).toString().split("\\r?\\n")) {
      String[] parts = line.split(":");
      if (realm == null) {
        realm = parts[1];
      } else {
        if (!realm.equals(parts[1])) {
          throw new RuntimeException("multiple realms in htdigest file not allowed.");
        }
      }
      htdigest.put(parts[0], new Digest(parts[0], parts[1], parts[2]));
    }

    this.realm = realm;
  }

  @Override
  public String realm() {
    return realm;
  }

  @Override
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(credentials)
      .onComplete(resultHandler);
  }

  @Override
  public Future<User> authenticate(JsonObject authInfo) {
    return authenticate(new HtdigestCredentials(authInfo));
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final HtdigestCredentials authInfo;
    try {
      authInfo = (HtdigestCredentials) credentials;
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    if (!htdigest.containsKey(authInfo.getUsername())) {
      return Future.failedFuture("Unknown username.");
    }

    final Digest credential = htdigest.get(authInfo.getUsername());

    if (!credential.realm.equals(authInfo.getRealm())) {
      return Future.failedFuture("Invalid realm.");
    }

    // calculate ha1
    final String ha1;
    if ("MD5-sess".equals(authInfo.getAlgorithm())) {
      ha1 = md5(credential.password + ":" + authInfo.getNonce() + ":" + authInfo.getCnonce());
    } else {
      ha1 = credential.password;
    }

    // calculate ha2
    final String ha2;
    if (authInfo.getQop() == null || "auth".equals(authInfo.getQop())) {
      ha2 = md5(authInfo.getMethod() + ":" + authInfo.getUri());
    } else if ("auth-int".equals(authInfo.getQop())) {
      return Future.failedFuture("qop: auth-int not supported.");
    } else {
      return Future.failedFuture("Invalid qop.");
    }

    // calculate request digest
    final String digest;
    if (authInfo.getQop() == null) {
      // For RFC 2069 compatibility
      digest = md5(ha1 + ":" + authInfo.getNonce() + ":" + ha2);
    } else {
      digest = md5(ha1 + ":" + authInfo.getNonce() + ":" + authInfo.getNc() + ":" + authInfo.getCnonce() + ":" + authInfo.getQop() + ":" + ha2);
    }

    if (digest.equals(authInfo.getResponse())) {
      User user = User.create(new JsonObject().put("username", credential.username).put("realm", credential.realm));
      // metadata "amr"
      user.principal().put("amr", Collections.singletonList("pwd"));

      return Future.succeededFuture(user);
    } else {
      return Future.failedFuture("Bad response");
    }
  }

  private static synchronized String md5(String payload) {
    MD5.reset();
    return base16Encode(MD5.digest(payload.getBytes(StandardCharsets.UTF_8)));
  }
}
