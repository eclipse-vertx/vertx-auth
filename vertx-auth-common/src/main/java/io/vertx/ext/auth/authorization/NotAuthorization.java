/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 4
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.authorization.impl.NotAuthorizationImpl;

/**
 * Allows to perform a logical 'not' of the specified authorization
 *
 * @author <a href="mailto:stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 */
@VertxGen
public interface NotAuthorization extends Authorization {

  static NotAuthorization create(Authorization authorization) {
    return new NotAuthorizationImpl(authorization);
  }

  Authorization getAuthorization();

}
