/*
 * Copyright (c) 2025 Sanju Thomas
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;

/**
 *
 */
@VertxGen
public interface ClientRegistrationProvider {
  Future<DCRResponse> create(String clientId);
  Future<DCRResponse> get(DCRRequest dcrRequest);
  Future<Void> delete(DCRRequest dcrRequest);
}