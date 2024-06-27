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
import io.vertx.ext.auth.htpasswd.impl.hash.APR1;
import io.vertx.ext.auth.htpasswd.impl.hash.Crypt;
import io.vertx.ext.auth.htpasswd.impl.hash.SHA1;

module io.vertx.auth.htpasswd {

  requires transitive io.vertx.auth.common;
  requires org.apache.commons.codec;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.htpasswd;

  provides HashingAlgorithm with APR1, Crypt, SHA1;

}
