/*
 * Copyright (c) 2021 Dmitry Novikov
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.ext.auth.otp.hotp;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.otp.Authenticator;
import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.hotp.impl.HotpAuthImpl;

import java.util.function.Function;

@VertxGen
public interface HotpAuth extends AuthenticationProvider {

  /**
   * Provide a {@link Function} that can fetch {@link Authenticator}s from a backend given an {@code identifier}
   * argument.
   *
   * The function signature is as follows:
   *
   * {@code (id) -> Future<Authenticator>}
   *
   * <ul>
   *   <li>{@code id} the identifier to lookup.</li>
   *   <li>{@link Future} async result with a authenticator.</li>
   * </ul>
   *
   * @param fetcher fetcher function.
   * @return fluent self.
   */
  @Fluent
  HotpAuth authenticatorFetcher(Function<String, Future<Authenticator>> fetcher);

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
  HotpAuth authenticatorUpdater(Function<Authenticator, Future<Void>> updater);

  Future<Authenticator> createAuthenticator(String id, OtpKey otpKey);

  String generateUri(OtpKey otpKey, long counter, String issuer, String user, String label);

  default String generateUri(OtpKey otpKey, long counter, String issuer, String user) {
    return generateUri(otpKey, counter, issuer, user, null);
  }

  default String generateUri(OtpKey otpKey, long counter, String label) {
    return generateUri(otpKey, counter, null, null, label);
  }

  static HotpAuth create() {
    return create(new HotpAuthOptions());
  }

  static HotpAuth create(HotpAuthOptions hotpAuthOptions) {
    return new HotpAuthImpl(hotpAuthOptions);
  }
}
