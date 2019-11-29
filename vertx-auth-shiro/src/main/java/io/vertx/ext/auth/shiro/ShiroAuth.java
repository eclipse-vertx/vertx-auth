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

package io.vertx.ext.auth.shiro;

import org.apache.shiro.realm.Realm;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.shiro.impl.ShiroAuthProviderImpl;

/**
 * Factory interface for creating Apache Shiro based {@link io.vertx.ext.auth.AuthProvider} instances.
 * @deprecated ShiroAuth has been replaced by {@code io.vertx.ext.auth.properties.PropertyFileAuthentication} and {@code io.vertx.ext.auth.ldap.LdapAuthentication}
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
@Deprecated
public interface ShiroAuth extends AuthProvider {

  /**
   * Create a Shiro auth provider
   * @param vertx  the Vert.x instance
   * @param realm  the Shiro realm
   * @return  the auth provider
   */
  @GenIgnore
  static ShiroAuth create(Vertx vertx, Realm realm) {
    return new ShiroAuthProviderImpl(vertx, realm);
  }

  /**
   * Create a Shiro auth provider
   * @param vertx  the Vert.x instance
   * @param options the Shiro configuration options
   * @return  the auth provider
   */
  static ShiroAuth create(Vertx vertx, ShiroAuthOptions options) {
    return ShiroAuthProviderImpl.create(vertx, options);
  }

}
