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
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.webauthn.impl.WebAuthnImpl;
import io.vertx.ext.auth.webauthn.store.AuthenticatorStore;

/**
 * Factory interface for creating WebAuthN based {@link io.vertx.ext.auth.authentication.AuthenticationProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface WebAuthn extends AuthenticationProvider {

  /**
   * Create a WebAuthN auth provider
   *
   * @param vertx the Vertx instance.
   * @return the auth provider.
   */
  static WebAuthn create(Vertx vertx) {
    return create(vertx, new WebAuthnOptions());
  }

  /**
   * Create a WebAuthN auth provider
   *
   * @param vertx the Vertx instance.
   * @param options the custom options to the provider.
   * @return the auth provider.
   */
  static WebAuthn create(Vertx vertx, WebAuthnOptions options) {
    return new WebAuthnImpl(vertx, options);
  }

  /**
   * Set's the authenticator store. The store implementation should be responsible to load the required data
   * from a database.
   *
   * @param store the user store used to load credentials.
   * @return fluent self
   */
  @Fluent
  WebAuthn setAuthenticatorStore(AuthenticatorStore store);

  /**
   * Gets a challenge and any other parameters for the {@code navigator.credentials.create()} call.
   *
   * The object being returned is described here <a href="https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions">https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions</a>
   * @param user    - the user object with name and optionally displayName and icon
   * @param handler server encoded make credentials request
   * @return fluent self
   */
  @Fluent
  WebAuthn createCredentialsOptions(JsonObject user, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Same as {@link #createCredentialsOptions(JsonObject, Handler)} but returning a Future.
   */
  default Future<JsonObject> createCredentialsOptions(JsonObject user) {
    Promise<JsonObject> promise = Promise.promise();
    createCredentialsOptions(user, promise);
    return promise.future();
  }

  /**
   * Creates an assertion challenge and any other parameters for the {@code navigator.credentials.get()} call.
   * If the auth provider is configured with {@code RequireResidentKey} and the username is null then the
   * generated assertion will be a RK assertion (Usernameless).
   *
   * The object being returned is described here <a href="https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions">https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions</a>
   *
   * @param name the unique user identified
   * @param handler server encoded get assertion request
   * @return fluent self.
   */
  @Fluent
  WebAuthn getCredentialsOptions(@Nullable String name, Handler<AsyncResult<JsonObject>> handler);

  /**
   * Same as {@link #getCredentialsOptions(String, Handler)} but returning a Future.
   */
  default Future<JsonObject> getCredentialsOptions(@Nullable String username) {
    Promise<JsonObject> promise = Promise.promise();
    getCredentialsOptions(username, promise);
    return promise.future();
  }
}
