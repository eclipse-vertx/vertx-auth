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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;

/**
 * AccessToken extension to the User interface
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface AccessToken extends User {

  /**
   * Check if the access token is expired or not.
   */
  boolean expired();

  /**
   * Refresh the access token
   *
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken refresh(Handler<AsyncResult<Void>> callback);

  /**
   * Revoke access or refresh token
   *
   * @param token_type - A String containing the type of token to revoke. Should be either "access_token" or "refresh_token".
   * @param callback - The callback function returning the results.
   */
  @Fluent
  AccessToken revoke(String token_type, Handler<AsyncResult<Void>> callback);
}
