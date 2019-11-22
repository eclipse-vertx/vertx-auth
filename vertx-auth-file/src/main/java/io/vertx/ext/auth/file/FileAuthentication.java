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
package io.vertx.ext.auth.file;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.file.impl.FileAuthenticationImpl;

/**
 * Factory interface for creating property file based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface FileAuthentication extends AuthProvider {

  /**
   * Create a File authentication provider
   * 
   * @param vertx  the Vert.x instance
   * @param realm  the path
   * @return  the authentication provider
   */
  @GenIgnore
  static FileAuthentication create(Vertx vertx, String path) {
    return new FileAuthenticationImpl(vertx, path);
  }

}
