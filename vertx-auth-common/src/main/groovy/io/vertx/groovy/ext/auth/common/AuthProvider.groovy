/*
 * Copyright 2014 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.vertx.groovy.ext.auth.common;
import groovy.transform.CompileStatic
import io.vertx.lang.groovy.InternalHelper
import io.vertx.core.AsyncResult
import io.vertx.core.Handler
/**
 *
 * User-facing interface for authenticating users.
*/
@CompileStatic
public class AuthProvider {
  final def io.vertx.ext.auth.AuthProvider delegate;
  public AuthProvider(io.vertx.ext.auth.AuthProvider delegate) {
    this.delegate = delegate;
  }
  public Object getDelegate() {
    return delegate;
  }
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
   * If the user is successfully authenticated a {@link io.vertx.groovy.ext.auth.common.User} object is passed to the handler in an {@link io.vertx.core.AsyncResult}.
   * The user object can then be used for authorisation.
   * @param authInfo The auth information
   * @param resultHandler The result handler
   */
  public void authenticate(Map<String, Object> authInfo, Handler<AsyncResult<User>> resultHandler) {
    this.delegate.authenticate(authInfo != null ? new io.vertx.core.json.JsonObject(authInfo) : null, new Handler<AsyncResult<io.vertx.ext.auth.User>>() {
      public void handle(AsyncResult<io.vertx.ext.auth.User> event) {
        AsyncResult<User> f
        if (event.succeeded()) {
          f = InternalHelper.<User>result(new User(event.result()))
        } else {
          f = InternalHelper.<User>failure(event.cause())
        }
        resultHandler.handle(f)
      }
    });
  }
}
