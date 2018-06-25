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
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

/**
 * Functional interface that allows users to implement custom RBAC verifiers for OAuth2/OpenId Connect.
 *
 * Users are to implement the <code>isAuthorized</code> method to verify authorities. For provides that do not
 * export the permissions/roles in the token, this interface allows you to communicate with 3rd party services
 * such as graph APIs to collect the required data.
 *
 * The contract is that once an authority is checked for a given user, it's value is cached during the execution
 * of the request. If a user is stored to a persistent storage, or the token is introspected, the cache is cleared
 * and a new call will be handled to the implementation.
 */
@VertxGen
@FunctionalInterface
public interface OAuth2RBAC {

  /**
   * This method should verify if the user has the given authority and return either a boolean value or an error.
   *
   * Note that false and errors are not the same. A user might not have a given authority but that doesn't mean that
   * there was an error during the call.
   *
   * @param user the given user to assert on
   * @param authority the authority to lookup
   * @param handler the result handler.
   */
  void isAuthorized(AccessToken user, String authority, Handler<AsyncResult<Boolean>> handler);
}
