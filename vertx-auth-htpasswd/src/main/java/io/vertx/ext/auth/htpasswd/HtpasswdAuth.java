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
package io.vertx.ext.auth.htpasswd;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.htpasswd.impl.HtpasswdAuthImpl;

/**
 * An extension of AuthProvider which is using htpasswd file as store
 *
 * @author Neven Radovanović
 */
@VertxGen
public interface HtpasswdAuth extends AuthProvider {

  static HtpasswdAuth create(Vertx vertx) {
    return new HtpasswdAuthImpl(vertx, new HtpasswdAuthOptions());
  }

  static HtpasswdAuth create(Vertx vertx, HtpasswdAuthOptions htpasswdAuthOptions) {
    return new HtpasswdAuthImpl(vertx, htpasswdAuthOptions);
  }

}
