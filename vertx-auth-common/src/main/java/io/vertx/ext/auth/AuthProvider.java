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

package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;

/**
 *
 * User-facing interface for authenticating users.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface AuthProvider {

  /**
   * Authenticate a user.
   * <p>
   * The first argument is a JSON object containing information for authenticating the user. What this actually contains
   * depends on the specific implementation. In the case of a simple username/password based
   * authentication it is likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username": "tim",
   *     "password": "mypassword"
   *   }
   * </pre>
   * For other types of authentication it contain different information - for example a JWT token or OAuth bearer token.
   * <p>
   * If the user is successfully authenticated a {@link User} object is passed to the handler in an {@link io.vertx.core.AsyncResult}.
   * The user object can then be used for authorisation.
   *
   * @param authInfo  The auth information
   * @param resultHandler  The result handler
   */
  void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler);

  /**
   * Authenticate a user.
   * <p>
   * The first argument is a JSON object containing information for authenticating the user. What this actually contains
   * depends on the specific implementation. In the case of a simple username/password based
   * authentication it is likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username": "tim",
   *     "password": "mypassword"
   *   }
   * </pre>
   * For other types of authentication it contain different information - for example a JWT token or OAuth bearer token.
   * <p>
   * If the user is successfully authenticated a {@link User} object is passed to the handler in an {@link io.vertx.core.AsyncResult}.
   * The user object can then be used for authorisation.
   *
   * @param authInfo  The auth information
   * @return The result future
   */
  default Future<User> authenticate(JsonObject authInfo) {
    Promise<User> promise = Promise.promise();
    authenticate(authInfo, promise);
    return promise.future();
  }
}
