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
package io.vertx.ext.auth.webauthn4j;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.webauthn4j.impl.WebAuthn4JImpl;

/**
 * Factory interface for creating WebAuthN based {@link io.vertx.ext.auth.authentication.AuthenticationProvider} instances.
 *
 * @author Paulo Lopes
 */
@VertxGen
public interface WebAuthn4J extends AuthenticationProvider {

  /**
   * Create a WebAuthN auth provider
   *
   * @param vertx the Vertx instance.
   * @return the auth provider.
   */
  static WebAuthn4J create(Vertx vertx) {
    return create(vertx, new WebAuthn4JOptions());
  }

  /**
   * Create a WebAuthN auth provider
   *
   * @param vertx   the Vertx instance.
   * @param options the custom options to the provider.
   * @return the auth provider.
   */
  static WebAuthn4J create(Vertx vertx, WebAuthn4JOptions options) {
    return new WebAuthn4JImpl(vertx, options);
  }

  /**
   * Gets a challenge and any other parameters for the {@code navigator.credentials.create()} call.
   * <p>
   * The object being returned is described here <a href="https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions">https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions</a>
   *
   * @param user    - the user object with name and optionally displayName and icon
   * @return a future notified with the encoded make credentials request
   */
  Future<JsonObject> createCredentialsOptions(JsonObject user);

  /**
   * Creates an assertion challenge and any other parameters for the {@code navigator.credentials.get()} call.
   * If the auth provider is configured with {@code RequireResidentKey} and the username is null then the
   * generated assertion will be a RK assertion (Usernameless).
   * <p>
   * The object being returned is described here <a href="https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions">https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions</a>
   *
   * @param username    the unique user identified
   * @return a future notified with the server encoded get assertion request
   */
  Future<JsonObject> getCredentialsOptions(@Nullable String username);

  /**
   * Provide a {@link CredentialStorage} that can fetch {@link Authenticator}s from storage and update them.
   *
   * @param credentialStorage the storage abstraction for credentials.
   * @return fluent self.
   */
  @Fluent
  WebAuthn4J credentialStorage(CredentialStorage credentialStorage);
}
