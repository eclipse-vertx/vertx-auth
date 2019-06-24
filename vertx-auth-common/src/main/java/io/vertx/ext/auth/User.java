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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;

/**
 * Represents an authenticates User and contains operations to authorise the user.
 * <p>
 * Please consult the documentation for a detailed explanation.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface User {

  /**
   * Is the user authorised to
   *
   * @param authority  the authority - what this really means is determined by the specific implementation. It might
   *                   represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                   authority to a role in a roles based model, e.g. `role:admin`.
   * @param resultHandler  handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   *                       `true` if the they has the authority or `false` otherwise.
   * @return the User to enable fluent use
   */
  @Fluent
  User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler);

  /**
   * Is the user authorised to
   *
   * @param authority  the authority - what this really means is determined by the specific implementation. It might
   *                   represent a permission to access a resource e.g. `printers:printer34` or it might represent
   *                   authority to a role in a roles based model, e.g. `role:admin`.
   * @return Future handler that will be called with an {@link io.vertx.core.AsyncResult} containing the value
   *    *                       `true` if the they has the authority or `false` otherwise.
   */
  default Future<Boolean> isAuthorized(String authority) {
    Promise<Boolean> promise = Promise.promise();
    isAuthorized(authority, promise);
    return promise.future();
  }

  /**
   * The User object will cache any authorities that it knows it has to avoid hitting the
   * underlying auth provider each time.  Use this method if you want to clear this cache.
   *
   * @return the User to enable fluent use
   */
  @Fluent
  User clearCache();

  /**
   * Get the underlying principal for the User. What this actually returns depends on the implementation.
   * For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
   * <pre>
   *   {
   *     "username", "tim"
   *   }
   * </pre>
   * @return JSON representation of the Principal
   */
  JsonObject principal();

  /**
   * Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
   * after it has been deserialized.
   *
   * @param authProvider  the AuthProvider - this must be the same type of AuthProvider that originally created the User
   */
  void setAuthProvider(AuthProvider authProvider);
}
