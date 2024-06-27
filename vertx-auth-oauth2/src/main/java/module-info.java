/*
 * Copyright (c) 2011-2024 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
module io.vertx.auth.oauth2 {

  requires transitive io.vertx.auth.common;
  requires io.vertx.core.logging;

  exports io.vertx.ext.auth.oauth2;
  exports io.vertx.ext.auth.oauth2.authorization;
  exports io.vertx.ext.auth.oauth2.providers;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

}
