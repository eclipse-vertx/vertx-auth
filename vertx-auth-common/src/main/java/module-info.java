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
import io.vertx.ext.auth.hashing.HashingAlgorithm;

module io.vertx.auth.common {

  requires transitive io.vertx.core;
  requires io.vertx.core.logging;
  requires java.naming;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth;
  exports io.vertx.ext.auth.authorization;
  exports io.vertx.ext.auth.authentication;
  exports io.vertx.ext.auth.hashing;
  exports io.vertx.ext.auth.prng;

  uses HashingAlgorithm;
  provides HashingAlgorithm with
    io.vertx.ext.auth.impl.hash.SHA1,
    io.vertx.ext.auth.impl.hash.SHA256,
    io.vertx.ext.auth.impl.hash.SHA512,
    io.vertx.ext.auth.impl.hash.PBKDF2;

  exports io.vertx.ext.auth.impl to io.vertx.auth.htdigest, io.vertx.auth.htpasswd, io.vertx.auth.oauth2, io.vertx.auth.otp, io.vertx.auth.sqlclient, io.vertx.auth.webauthn;
  exports io.vertx.ext.auth.impl.jose to io.vertx.auth.jwt, io.vertx.auth.oauth2, io.vertx.auth.webauthn, io.vertx.tests;
  exports io.vertx.ext.auth.impl.cose to io.vertx.auth.webauthn, io.vertx.tests;
  exports io.vertx.ext.auth.impl.asn to io.vertx.auth.webauthn;
  exports io.vertx.ext.auth.authorization.impl to io.vertx.auth.abac;
  exports io.vertx.ext.auth.impl.http to io.vertx.auth.oauth2, io.vertx.auth.webauthn;

}
