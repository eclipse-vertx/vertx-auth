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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.shiro.impl.ShiroAuthProviderImpl;
import org.apache.shiro.realm.Realm;

/**
 * Factory interface for creating Apache Shiro based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface ShiroAuth extends AuthProvider {

  /**
   * The default role prefix
   */
  String DEFAULT_ROLE_PREFIX = "role:";

  /**
   * Create a Shiro auth provider
   * @param vertx  the Vert.x instance
   * @param realmType  the Shiro realm type
   * @param config  the config
   * @return  the auth provider
   */
  static ShiroAuth create(Vertx vertx, ShiroAuthRealmType realmType, JsonObject config) {
    return ShiroAuthProviderImpl.create(vertx, realmType, config);
  }

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
   * Set the role prefix to distinguish from permissions when checking for isPermitted requests.
   * @param rolePrefix a Prefix e.g.: "role:"
   * @return a reference to this for fluency
   */
  ShiroAuth setRolePrefix(String rolePrefix);

}
