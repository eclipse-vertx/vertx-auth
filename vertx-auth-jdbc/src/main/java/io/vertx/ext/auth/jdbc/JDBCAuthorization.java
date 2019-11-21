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

package io.vertx.ext.auth.jdbc;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.AuthorizationProvider;
import io.vertx.ext.auth.jdbc.impl.JDBCAuthorizationImpl;
import io.vertx.ext.jdbc.JDBCClient;

/**
 * Factory interface for creating {@link io.vertx.ext.auth.AuthorizationProvider} instances that use the Vert.x JDBC client.
 *
 * @author <a href="mail://stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface JDBCAuthorization extends AuthorizationProvider {

  /**
   * Create a JDBC authorization provider implementation
   *
   * @param options JDBCAuthorizationOptions
   * @return  the auth provider
   */
  static JDBCAuthorization create(JDBCClient client, JDBCAuthorizationOptions options) {
    return new JDBCAuthorizationImpl(client, options);
  }

}
