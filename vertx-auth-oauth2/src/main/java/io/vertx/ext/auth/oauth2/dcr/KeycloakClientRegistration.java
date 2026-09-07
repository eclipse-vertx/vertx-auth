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
package io.vertx.ext.auth.oauth2.dcr;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.ClientRegistrationProvider;
import io.vertx.ext.auth.oauth2.DCROptions;
import io.vertx.ext.auth.oauth2.dcr.impl.KeycloakClientRegistrationImpl;

public interface KeycloakClientRegistration extends ClientRegistrationProvider {

  static KeycloakClientRegistration create(Vertx vertx, DCROptions dcrOptions) {
    return new KeycloakClientRegistrationImpl(vertx, dcrOptions);
  }
}
