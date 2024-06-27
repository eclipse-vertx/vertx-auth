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
import io.vertx.ext.auth.webauthn.impl.attestation.*;

module io.vertx.auth.webauthn {

  requires transitive io.vertx.auth.common;
  requires io.vertx.core.logging;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.webauthn;
  exports io.vertx.ext.auth.webauthn.impl to io.vertx.tests;
  exports io.vertx.ext.auth.webauthn.impl.metadata to io.vertx.tests;

  // Consider having this as an official SPI package
  uses Attestation;
  provides Attestation with NoneAttestation, FidoU2fAttestation, PackedAttestation, AndroidKeyAttestation, AndroidSafetynetAttestation, TPMAttestation, AppleAttestation;

}
