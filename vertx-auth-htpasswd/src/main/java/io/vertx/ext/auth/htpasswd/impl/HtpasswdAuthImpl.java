/*
 * Copyright 2014 Red Hat, Inc.
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
package io.vertx.ext.auth.htpasswd.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.htpasswd.HtpasswdAuth;
import io.vertx.ext.auth.htpasswd.HtpasswdAuthOptions;
import io.vertx.ext.auth.htpasswd.impl.hash.Plaintext;

/**
 * An implementation of {@link HtpasswdAuth}
 *
 * @author Neven Radovanović
 */
public class HtpasswdAuthImpl implements HtpasswdAuth {

  private final HashingStrategy strategy = HashingStrategy.load();

  private final Map<String, String> htUsers = new HashMap<>();

  public HtpasswdAuthImpl(Vertx vertx, HtpasswdAuthOptions options) {
    for (String line : vertx.fileSystem().readFileBlocking(options.getHtpasswdFile()).toString().split("\\r?\\n")) {
      line = line.trim();

      if (line.isEmpty() || line.startsWith("#")) continue;

      Pattern entry = Pattern.compile("^([^:]+):(.+)");
      Matcher m = entry.matcher(line);
      if (m.matches()) {
        htUsers.put(m.group(1), m.group(2));
      }
    }

    // handle the plain text vs crypt
    if (options.isPlainTextEnabled()) {
      // this will show a warning in the log
      strategy.put("", new Plaintext());
    }
  }

  @Override
  public Future<User> authenticate(JsonObject authInfo) {
    return authenticate(new UsernamePasswordCredentials(authInfo));
  }

  @Override
  public Future<User> authenticate(Credentials credential) {

    final UsernamePasswordCredentials authInfo;
    try {
      authInfo = (UsernamePasswordCredentials) credential;
      authInfo.checkValid(null);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    if (!htUsers.containsKey(authInfo.getUsername())) {
      return Future.failedFuture("Unknown username.");
    }

    if (strategy.verify(htUsers.get(authInfo.getUsername()), authInfo.getPassword())) {
      return Future.succeededFuture(User.create(new JsonObject().put("username", authInfo.getUsername())));
    } else {
      return Future.failedFuture("Bad response");
    }
  }
}
