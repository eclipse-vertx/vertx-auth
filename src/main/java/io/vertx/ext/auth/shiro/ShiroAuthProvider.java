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

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface ShiroAuthProvider extends AuthProvider {

  static ShiroAuthProvider create(Vertx vertx, ShiroAuthRealmType shiroAuthRealmType, JsonObject config) {
    return new ShiroAuthProviderImpl(vertx, shiroAuthRealmType, config);
  }

  @GenIgnore
  static ShiroAuthProvider create(Vertx vertx, ShiroAuthRealm shiroAuthRealm) {
    return new ShiroAuthProviderImpl(vertx, shiroAuthRealm);
  }
}
