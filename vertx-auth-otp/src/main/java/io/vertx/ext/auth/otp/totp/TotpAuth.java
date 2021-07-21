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

package io.vertx.ext.auth.otp.totp;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.Future;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.otp.Authenticator;
import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.totp.impl.TotpAuthImpl;

import java.util.function.Function;

/**
 * An extension of AuthProvider which uses the one time passwords based on time to perform authentication.
 *
 * @author Dmitry Novikov
 */
@VertxGen
public interface TotpAuth extends AuthenticationProvider {

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
  TotpAuth authenticatorFetcher(Function<String, Future<Authenticator>> fetcher);

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
  TotpAuth authenticatorUpdater(Function<Authenticator, Future<Void>> updater);

  /**
   * Creating authenticator from user id and key.
   *
   * @param id id user.
   * @param otpKey key of user used for auth.
   * @return {@link Authenticator} an object containing all the necessary information to authenticate a user.
   */
  Future<Authenticator> createAuthenticator(String id, OtpKey otpKey);

  /**
   * Creating URI for register in key in user device.
   *
   * @param otpKey user key.
   * @param period period of valid code.
   * @param issuer issuer of key.
   * @param user display name of user account.
   * @param label the label to identify which account a key is associated with.
   * @return uri containing the key.
   */
  String generateUri(OtpKey otpKey, long period, String issuer, String user, String label);

  /**
   * Creating URI for register in key in user device.
   *
   * @param otpKey user key.
   * @param period period of valid code.
   * @param issuer issuer of key.
   * @param user display name of user account.
   * @return uri containing the key.
   */
  default String generateUri(OtpKey otpKey, long period, String issuer, String user) {
    return generateUri(otpKey, period, issuer, user, null);
  }

  /**
   * Creating URI for register in key in user device.
   *
   * @param otpKey user key.
   * @param period period of valid code.
   * @param label the label to identify which account a key is associated with.
   * @return uri containing the key.
   */
  default String generateUri(OtpKey otpKey, long period, String label) {
    return generateUri(otpKey, period, null, null, label);
  }

  /**
   * Creates an instance of TotpAuth.
   *
   * @return the created instance of {@link TotpAuth}.
   */
  static TotpAuth create() {
    return create(new TotpAuthOptions());
  }

  /**
   * Creates an instance of TotpAuth.
   *
   * @param totpAuthOptions the config.
   * @return the created instance of {@link TotpAuth}.
   */
  static TotpAuth create(TotpAuthOptions totpAuthOptions) {
    return new TotpAuthImpl(totpAuthOptions);
  }
}
