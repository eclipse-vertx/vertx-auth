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
package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.htpasswd.impl.HtpasswdAuthImpl;

/**
 * An extension of AuthProvider which is using htpasswd file as store
 *
 * @author Neven Radovanović
 */
@VertxGen
public interface HtpasswdAuth extends AuthenticationProvider {

  static HtpasswdAuth create(Vertx vertx) {
    return new HtpasswdAuthImpl(vertx, new HtpasswdAuthOptions());
  }

  static HtpasswdAuth create(Vertx vertx, HtpasswdAuthOptions htpasswdAuthOptions) {
    return new HtpasswdAuthImpl(vertx, htpasswdAuthOptions);
  }

  /**
   * Authenticate a User using the specified {@link UsernamePasswordCredentials}
   *
   * @param credential
   * @param handler
   */
  void authenticate(UsernamePasswordCredentials credential, Handler<AsyncResult<User>> handler);

  /**
   * Authenticate a User using the specified {@link UsernamePasswordCredentials}
   *
   * @param credentials
   */
  default Future<User> authenticate(UsernamePasswordCredentials credentials) {
    Promise<User> promise = Promise.promise();
    authenticate(credentials, promise);
    return promise.future();
  }
}
