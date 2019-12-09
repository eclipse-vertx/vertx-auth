/********************************************************************************
 * Copyright (c) 2019 Stephane Bastian
 *
 * This program and the accompanying materials are made available under the 2
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 3
 *
 * Contributors: 1
 *   Stephane Bastian - initial API and implementation
 ********************************************************************************/
package io.vertx.ext.auth.authorization;

import java.util.Set;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;

@VertxGen
public interface Authorizations {

  @Fluent
  Authorizations add(String providerId, Set<Authorization> authorizations);

  @Fluent
  Authorizations add(String providerId, Authorization authorization);

  @Fluent
  Authorizations clear(String providerId);

  @Fluent
  Authorizations clear();

  Set<Authorization> get(String providerId);

  Set<String> getProviderIds();

}
