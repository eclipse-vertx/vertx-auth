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

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.AuthenticationProvider;
import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.hotp.impl.HotpAuthImpl;

@VertxGen
public interface HotpAuth extends AuthenticationProvider {

  void requestHotp(User user, Handler<AsyncResult<User>> resultHandler);

  void revokeHotp(User user, Handler<AsyncResult<User>> resultHandler);

  String generateUri(OtpKey otpKey, long counter, String issuer, String user, String label);

  default String generateUri(OtpKey otpKey, long counter, String issuer, String user) {
    return generateUri(otpKey, counter, issuer, user, null);
  }

  default String generateUri(OtpKey otpKey, long counter, String label) {
    return generateUri(otpKey, counter, null, null, label);
  }

  static HotpAuth create(HotpAuthOptions hotpAuthOptions) {
    return new HotpAuthImpl(hotpAuthOptions);
  }
}
