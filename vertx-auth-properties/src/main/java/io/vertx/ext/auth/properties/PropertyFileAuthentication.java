/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.properties;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.properties.impl.PropertyFileAuthenticationImpl;

/**
 * Factory interface for creating property file based {@link io.vertx.ext.auth.authentication.AuthenticationProvider} instances.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface PropertyFileAuthentication extends AuthenticationProvider {

  /**
   * Create a File authentication provider
   *
   * @param vertx  the Vert.x instance
   * @return  the authentication provider
   */
  static PropertyFileAuthentication create(Vertx vertx, String path) {
    return new PropertyFileAuthenticationImpl(vertx, path);
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
