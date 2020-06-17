/*
 * Copyright 2014 Red Hat, Inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Apache License v2.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * The Apache License v2.0 is available at
 * http://www.opensource.org/licenses/apache2.0.php
 *
 * You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.htdigest;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.htdigest.impl.HtdigestAuthImpl;

/**
 * An extension of AuthProvider which is using .htdigest file as store
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface HtdigestAuth extends AuthenticationProvider {

  /**
   * The property name to be used to set the name of the collection inside the config
   */
  String HTDIGEST_FILE = ".htdigest";

  /**
   * Creates an instance of HtdigestAuth.
   *
   * @return the created instance of {@link HtdigestAuth}s
   */
  static HtdigestAuth create(Vertx vertx) {
    return new HtdigestAuthImpl(vertx, HTDIGEST_FILE);
  }

  /**
   * Creates an instance of HtdigestAuth by using the given htfile file.
   *
   * @param htfile the existing htfile.
   * @return the created instance of {@link HtdigestAuth}s
   */
  static HtdigestAuth create(Vertx vertx, String htfile) {
    return new HtdigestAuthImpl(vertx, htfile);
  }

  /**
   * Return the currently used realm
   *
   * @return the realm
   */
  String realm();
}
