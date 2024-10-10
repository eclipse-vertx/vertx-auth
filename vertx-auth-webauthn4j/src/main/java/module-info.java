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
module io.vertx.auth.webauthn4j {

  requires io.vertx.auth.common;
  requires io.vertx.core.logging;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static io.vertx.docgen;
  requires webauthn4j.metadata.async;
  requires webauthn4j.core.async;
  requires webauthn4j.core;
  requires webauthn4j.metadata;

  exports io.vertx.ext.auth.webauthn4j;
  exports io.vertx.ext.auth.webauthn4j.impl to io.vertx.tests;
}
