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
import io.vertx.ext.auth.htdigest.HtdigestAuth;
import io.vertx.ext.auth.impl.UserImpl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

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
  public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
    String username = authInfo.getString("username");

    // Null or empty username is invalid
    if (username == null || username.length() == 0) {
      resultHandler.handle((Future.failedFuture("Username must be set for authentication.")));
      return;
    }

    if (!htdigest.containsKey(username)) {
      resultHandler.handle((Future.failedFuture("Unknown username.")));
      return;
    }

    String realm = authInfo.getString("realm");

    // Null realm is invalid
    if (realm == null) {
      resultHandler.handle((Future.failedFuture("Realm must be set for authentication.")));
      return;
    }

    final Digest credential = htdigest.get(username);

    if (!credential.realm.equals(realm)) {
      resultHandler.handle((Future.failedFuture("Invalid realm.")));
      return;
    }

    // calculate ha1
    final String ha1;
    if ("MD5-sess".equals(authInfo.getString("algorithm"))) {
      ha1=md5(credential.password + ":" + authInfo.getString("nonce") + ":" + authInfo.getString("cnonce"));
    } else {
      ha1 = credential.password;
    }

    // calculate ha2
    final String ha2;
    if (!authInfo.containsKey("qop") || "auth".equals(authInfo.getString("qop"))) {
      ha2 = md5(authInfo.getString("method") + ":" + authInfo.getString("uri"));
    } else if ("auth-int".equals(authInfo.getString("qop"))){
      resultHandler.handle((Future.failedFuture("qop: auth-int not supported.")));
      return;
    } else {
      resultHandler.handle((Future.failedFuture("Invalid qop.")));
      return;
    }

    // calculate request digest
    final String digest;
    if (!authInfo.containsKey("qop")) {
      // For RFC 2069 compatibility
      digest = md5(ha1 + ":" + authInfo.getString("nonce") + ":" + ha2);
    } else {
      digest = md5(ha1 + ":" + authInfo.getString("nonce") + ":" + authInfo.getString("nc") + ":" + authInfo.getString("cnonce") + ":" + authInfo.getString("qop") + ":" + ha2);
    }

    if (digest.equals(authInfo.getString("response"))) {
      resultHandler.handle(Future.succeededFuture(new UserImpl(new JsonObject().put("username", credential.username).put("realm", credential.realm))));
    } else {
      resultHandler.handle(Future.failedFuture("Bad response"));
    }
  }

  private final static char[] hexArray = "0123456789abcdef".toCharArray();

  private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  private static synchronized String md5(String payload) {
    MD5.reset();
    return bytesToHex(MD5.digest(payload.getBytes()));
  }
}
