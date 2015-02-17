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

package io.vertx.ext.auth.shiro.impl;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.ext.auth.shiro.ShiroAuthRealm;
import io.vertx.ext.auth.shiro.ShiroAuthRealmType;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class ShiroAuthServiceImpl extends AuthServiceImpl {

  public static ShiroAuthRealm createRealm(ShiroAuthRealmType type) {

    ShiroAuthRealm authRealm;
    switch (type) {
      case PROPERTIES:
        authRealm = new PropertiesAuthRealm();
        break;
      case JDBC:
        // TODO
        throw new UnsupportedOperationException();
      case LDAP:
        authRealm = new LDAPAuthRealm();
        break;
      default:
        throw new IllegalArgumentException("Invalid shiro auth realm type: " + type);
    }
    return authRealm;
  }

  public ShiroAuthServiceImpl(Vertx vertx, ShiroAuthRealm authRealm, JsonObject config, long reaperPeriod) {
    super(vertx, config, new ShiroAuthProvider(vertx, authRealm), reaperPeriod);
    authRealm.init(config);
  }
}
