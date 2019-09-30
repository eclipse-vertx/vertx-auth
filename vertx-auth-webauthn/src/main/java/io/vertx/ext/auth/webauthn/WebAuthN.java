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

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.impl.AuthenticatorData;
import io.vertx.ext.auth.webauthn.impl.WebAuthNImpl;

import java.util.List;

import static io.vertx.codegen.annotations.GenIgnore.PERMITTED_TYPE;

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

  /**
   * Generates makeCredentials request
   *
   * @param username    - username
   * @param displayName - user's personal display name
   * @param id          - user's base64url encoded id
   * @return server encoded make credentials request
   */
  default JsonObject generateServerCredentialsChallenge(String username, String displayName, String id) {
    return generateServerCredentialsChallenge(username, displayName, id, null);
  }

  /**
   * Generates makeCredentials request
   *
   * @param username    - username
   * @param displayName - user's personal display name
   * @param id          - user's base64url encoded id
   * @param type        - optional Credentials Challenge Type
   * @return server encoded make credentials request
   */
  JsonObject generateServerCredentialsChallenge(String username, String displayName, String id, CredentialsChallengeType type);

  /**
   * Generates getAssertion request
   *
   * @param authenticators list of registered authenticators credential Ids
   * @return server encoded get assertion request
   */
  JsonObject generateServerGetAssertion(List<String> authenticators);

  @GenIgnore(PERMITTED_TYPE)
  void authenticate(WebAuthNInfo authInfo, Handler<AsyncResult<User>> handler);

  @GenIgnore(PERMITTED_TYPE)
  default Future<User> authenticate(WebAuthNInfo authInfo) {
    Promise<User> promise = Promise.promise();
    authenticate(authInfo, promise);
    return promise.future();
  }

  @Override
  default void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> handler) {
    authenticate(new WebAuthNInfo(authInfo), handler);
  }
}
