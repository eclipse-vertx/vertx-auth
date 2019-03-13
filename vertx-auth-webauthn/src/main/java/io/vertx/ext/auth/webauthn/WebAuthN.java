/*
 * Copyright 2019 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.webauthn;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.webauthn.impl.WebAuthNImpl;

import java.util.List;

/**
 * Factory interface for creating WebAuthN based {@link io.vertx.ext.auth.AuthProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface WebAuthN extends AuthProvider {

  /**
   * Create a WebAuthN auth provider
   *
   * @param vertx the Vertx instance
   * @return the auth provider
   */
  static WebAuthN create(Vertx vertx, WebAuthNOptions options) {
    return new WebAuthNImpl(vertx, options);
  }

  @Fluent
  WebAuthN webAuthNStore(WebAuthNStore store);

  /**
   * Generates makeCredentials request
   *
   * @param username    - username
   * @param displayName - user's personal display name
   * @param handler a callback  with server encoded make credentials request
   * @return fluent self
   */
  @Fluent
  WebAuthN generateServerMakeCredRequest(String username, String displayName, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Generates getAssertion request
   *
   * @param username the username to challenge
   * @param handler the callback with server encoded get assertion request
   * @return fluent self
   */
  @Fluent
  WebAuthN generateServerGetAssertion(String username, Handler<AsyncResult<JsonObject>> handler);
}
