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

package io.vertx.ext.auth;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authentication.AuthenticationProvider;

/**
 *
 * User-facing interface for authenticating users.
 *
 * @author <a href="http://tfox.org">Tim Fox</a>
 * @deprecated This interface was quite opionated. The new alternative is to use one of the specific interfaces: {@link AuthenticationProvider} or {@link io.vertx.ext.auth.authorization.AuthorizationProvider}
 */
@VertxGen
@Deprecated
public interface AuthProvider extends AuthenticationProvider {
}
