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

package io.vertx.ext.auth.authentication;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;

/**
 *
 * User-facing interface for authenticating users.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface AuthenticationProvider {

  /**
   * Authenticate a user.
   * <p>
   * The first argument is a Credentials object containing information for authenticating the user.
   * What this actually contains depends on the specific implementation.
   *
   * If the user is successfully authenticated a {@link User} object is passed to the handler in an {@link AsyncResult}.
   * The user object can then be used for authorisation.
   *
   * @param credentials  The credentials
   * @param resultHandler  The result handler
   */
  @GenIgnore(GenIgnore.PERMITTED_TYPE)
  @Deprecated
  default void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(credentials)
      .onComplete(resultHandler);
  }

  /**
   * Authenticate a user.
   * <p>
   * The first argument is a Credentials object containing information for authenticating the user.
   * What this actually contains depends on the specific implementation.
   *
   * @see AuthenticationProvider#authenticate(Credentials, Handler)
   * @param credentials  The credentials
   * @return The result future
   */
  Future<User> authenticate(Credentials credentials);
}
