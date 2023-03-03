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

import java.util.List;
import java.util.function.Function;

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
   * Gets a challenge and any other parameters for the {@code navigator.credentials.create()} call.
   *
   * The object being returned is described here <a href="https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions">https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions</a>
   * @param user    - the user object with name and optionally displayName and icon
   * @param handler server encoded make credentials request
   * @return fluent self
   */
  @Fluent
  @Deprecated
  default WebAuthn createCredentialsOptions(JsonObject user, Handler<AsyncResult<JsonObject>> handler) {
    createCredentialsOptions(user)
      .onComplete(handler);

    return this;
  }

  /**
   * Same as {@link #createCredentialsOptions(JsonObject, Handler)} but returning a Future.
   */
  Future<JsonObject> createCredentialsOptions(JsonObject user);

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
  @Deprecated
  default WebAuthn getCredentialsOptions(@Nullable String name, Handler<AsyncResult<JsonObject>> handler) {
    getCredentialsOptions(name)
      .onComplete(handler);

    return this;
  }

  /**
   * Same as {@link #getCredentialsOptions(String, Handler)} but returning a Future.
   */
  Future<JsonObject> getCredentialsOptions(@Nullable String username);

  /**
   * Provide a {@link Function} that can fetch {@link Authenticator}s from a backend given the incomplete
   * {@link Authenticator} argument.
   *
   * The implementation must consider the following fields <strong>exclusively</strong>, while performing the lookup:
   * <ul>
   *   <li>{@link Authenticator#getUserName()}</li>
   *   <li>{@link Authenticator#getCredID()} ()}</li>
   * </ul>
   *
   * It may return more than 1 result, for example when a user can be identified using different modalities.
   * To signal that a user is not allowed/present on the system, a failure should be returned, not {@code null}.
   *
   * The function signature is as follows:
   *
   * {@code (Authenticator) -> Future<List<Authenticator>>>}
   *
   * <ul>
   *   <li>{@link Authenticator} the incomplete authenticator data to lookup.</li>
   *   <li>{@link Future}async result with a list of authenticators.</li>
   * </ul>
   *
   * @param fetcher fetcher function.
   * @return fluent self.
   */
  @Fluent
  WebAuthn authenticatorFetcher(Function<Authenticator, Future<List<Authenticator>>> fetcher);

  /**
   * Provide a {@link Function} that can update or insert a {@link Authenticator}.
   * The function <strong>should</strong> store a given authenticator to a persistence storage.
   *
   * When an authenticator is already present, this method <strong>must</strong> at least update
   * {@link Authenticator#getCounter()}, and is not required to perform any other update.
   *
   * For new authenticators, the whole object data <strong>must</strong> be persisted.
   *
   * The function signature is as follows:
   *
   * {@code (Authenticator) -> Future<Void>}
   *
   * <ul>
   *   <li>{@link Authenticator} the authenticator data to update.</li>
   *   <li>{@link Future}async result of the operation.</li>
   * </ul>
   *
   * @param updater updater function.
   * @return fluent self.
   */
  @Fluent
  WebAuthn authenticatorUpdater(Function<Authenticator, Future<Void>> updater);

  /**
   * Getter to the instance FIDO2 Meta Data Service.
   * @return the MDS instance.
   */
  MetaDataService metaDataService();
}
