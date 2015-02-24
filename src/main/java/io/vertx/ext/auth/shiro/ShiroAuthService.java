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
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.shiro.impl.ShiroAuthRealmImpl;
import io.vertx.ext.auth.shiro.impl.ShiroAuthServiceImpl;
import org.apache.shiro.realm.Realm;

/**
 * An Auth service implementation that uses Apache Shiro internally.
 * <p>
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface ShiroAuthService extends AuthService {

  /**
   * Create an auth service using the specified auth realm type.
   *
   * @param vertx  the Vert.x intance
   * @param authRealmType  the auth realm type
   * @param config  the config to pass to the provider
   * @return the auth service
   */
  static AuthService create(Vertx vertx, ShiroAuthRealmType authRealmType, JsonObject config) {
    return new ShiroAuthServiceImpl(vertx, ShiroAuthServiceImpl.createRealm(authRealmType), config);
  }

  /**
   * Create an auth service using the specified Shiro Realm instance
   *
   * @param vertx  the Vert.x intance
   * @param shiroRealm  the Shiro realm instance.
   * @param config  the config to pass to the provider
   * @return the auth service
   */
  @GenIgnore
  static AuthService createFromRealm(Vertx vertx, Realm shiroRealm, JsonObject config) {
    return new ShiroAuthServiceImpl(vertx, new ShiroAuthRealmImpl(shiroRealm), config);
  }

}
