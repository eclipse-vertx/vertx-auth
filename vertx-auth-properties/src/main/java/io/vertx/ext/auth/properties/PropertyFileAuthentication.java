/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.properties;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
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
   * @param vertx the Vert.x instance
   * @return the authentication provider
   */
  static PropertyFileAuthentication create(Vertx vertx, String path) {
    return new PropertyFileAuthenticationImpl(vertx, path);
  }

  /**
   * Create a File authentication provider from the given property file content. Use this when the
   * content is not stored on the file system, e.g.: loaded from the classpath, a remote location
   * or preprocessed in memory.
   *
   * @param vertx  the Vert.x instance
   * @param buffer the property file content
   * @return the authentication provider
   */
  static PropertyFileAuthentication create(Vertx vertx, Buffer buffer) {
    return new PropertyFileAuthenticationImpl(vertx, buffer);
  }
}
