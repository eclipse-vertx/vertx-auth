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

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;

import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import static io.vertx.codegen.annotations.GenIgnore.PERMITTED_TYPE;

@VertxGen
public interface Authorizations {

  @Fluent
  Authorizations add(String providerId, Authorization authorization);

  @Fluent
  Authorizations put(String providerId, Set<Authorization> authorizations);

  boolean isEmpty();

  @Fluent
  Authorizations clear(String providerId);

  @Fluent
  Authorizations clearAll();

  boolean verify(Authorization resolvedAuthorization);

  @Fluent
  @GenIgnore(PERMITTED_TYPE)
  Authorizations forEach(BiConsumer<String, Authorization> consumer);

  @Fluent
  @GenIgnore(PERMITTED_TYPE)
  Authorizations forEach(String providerId, Consumer<Authorization> consumer);
}
