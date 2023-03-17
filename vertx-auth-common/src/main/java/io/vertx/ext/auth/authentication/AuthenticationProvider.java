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

package io.vertx.ext.auth.authentication;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.ext.auth.User;

/**
 * User-facing interface for authenticating users.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
public interface AuthenticationProvider {

  /**
   * Authenticate a user.
   * <p>
   * The first argument is a Credentials object containing information for authenticating the user.
   * What this actually contains depends on the specific implementation.
   *
   * @param credentials The credentials
   * @return The result future
   */
  Future<User> authenticate(Credentials credentials);
}
