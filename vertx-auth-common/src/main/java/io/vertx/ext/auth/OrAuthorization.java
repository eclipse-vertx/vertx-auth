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
package io.vertx.ext.auth;

import java.util.List;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.ext.auth.impl.OrAuthorizationImpl;

/**
 * Allows to perform a logical 'or' between several authorizations
 * 
 * @author <a href="mailto:stephane.bastian.dev@gmail.com">Stephane Bastian</a>
 * 
 */
@VertxGen
public interface OrAuthorization extends Authorization {

  static OrAuthorization create() {
    return new OrAuthorizationImpl();
  }

  List<Authorization> getAuthorizations();

  OrAuthorization addAuthorization(Authorization authorization);

}
