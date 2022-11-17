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

package io.vertx.ext.auth.otp.totp.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.otp.Authenticator;
import io.vertx.ext.auth.otp.OtpCredentials;
import io.vertx.ext.auth.otp.OtpKey;
import io.vertx.ext.auth.otp.impl.org.openauthentication.otp.OneTimePasswordAlgorithm;
import io.vertx.ext.auth.otp.totp.TotpAuth;
import io.vertx.ext.auth.otp.totp.TotpAuthOptions;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Function;

public class TotpAuthImpl implements TotpAuth {

  private final TotpAuthOptions totpAuthOptions;

  private Function<String, Future<Authenticator>> fetcher;
  private Function<Authenticator, Future<Void>> updater;

  public TotpAuthImpl(TotpAuthOptions totpAuthOptions) {
    if (totpAuthOptions == null) {
      throw new IllegalArgumentException("totpAuthOptions cannot null");
    }
    this.totpAuthOptions = totpAuthOptions;
  }

  @Override
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(credentials)
      .onComplete(resultHandler);
  }

  @Override
  public Future<User> authenticate(JsonObject credentials) {
    return authenticate(new OtpCredentials(credentials));
  }

  @Override
  public Future<User> authenticate(Credentials credentials) {
    final OtpCredentials authInfo;
    try {
      authInfo = (OtpCredentials) credentials;
      authInfo.checkValid(totpAuthOptions);
    } catch (RuntimeException e) {
      return Future.failedFuture(e);
    }

    return fetcher
      .apply(authInfo.getIdentifier())
      .compose(authenticator -> {
        if (authenticator == null) {
          return Future.failedFuture("user is not found");
        } else {
          String key = authenticator.getKey();
          String algorithm = authenticator.getAlgorithm();

          OtpKey otpKey = new OtpKey()
            .setKey(key)
            .setAlgorithm(algorithm);

          Integer authAttempts = authenticator.getAuthAttempts();
          authAttempts = authAttempts != null ? ++authAttempts : 1;
          authenticator.setAuthAttempts(authAttempts);

          String oneTimePassword;

          try {
            final long movingFactor = Instant.now().getEpochSecond() / totpAuthOptions.getPeriod();
            oneTimePassword = OneTimePasswordAlgorithm.generateOTP(otpKey.getKeyBytes(), movingFactor, totpAuthOptions.getPasswordLength(), false, -1);
          } catch (GeneralSecurityException e) {
            return Future.failedFuture(e);
          }

          if (MessageDigest.isEqual(oneTimePassword.getBytes(StandardCharsets.UTF_8), authInfo.getCode().getBytes(StandardCharsets.UTF_8))) {
            return updater.apply(authenticator)
              .compose(v -> Future.succeededFuture(createUser(authenticator)));
          }

          if (totpAuthOptions.isUsingAttemptsLimit() && authAttempts >= totpAuthOptions.getAuthAttemptsLimit()) {
            return updater.apply(authenticator)
              .compose(v -> Future.failedFuture("invalid code"));
          }

          return Future.failedFuture("invalid code");
        }
      });
  }

  @Override
  public TotpAuth authenticatorFetcher(Function<String, Future<Authenticator>> fetcher) {
    this.fetcher = fetcher;
    return this;
  }

  @Override
  public TotpAuth authenticatorUpdater(Function<Authenticator, Future<Void>> updater) {
    this.updater = updater;
    return this;
  }

  @Override
  public Future<Authenticator> createAuthenticator(String id, OtpKey otpKey) {
    // Create user in the database
    final Authenticator authenticator = new Authenticator(true)
      .setIdentifier(id)
      .setKey(otpKey.getKey())
      .setAlgorithm(otpKey.getAlgorithm())
      .setPeriod(totpAuthOptions.getPeriod());

    return updater
      .apply(authenticator)
      .map(authenticator);
  }

  @Override
  public String generateUri(OtpKey otpKey, String issuer, String user, String label) {
    try {
      if (label == null) {
        if (issuer == null) {
          throw new IllegalArgumentException("label and issuer cannot all be null");
        }
        if (user == null) {
          label = URLEncoder.encode(issuer, "UTF8");
        } else {
          label = URLEncoder.encode(issuer, "UTF8") + ":" + URLEncoder.encode(user, "UTF8");
        }
      }

      // build the parameter
      StringBuilder sb = new StringBuilder();
      // secret is required
      sb.append("secret=").append(otpKey.getKey());
      // issuer is strongly recommended
      if (issuer != null) {
        sb.append("&issuer=").append(URLEncoder.encode(issuer, "UTF8"));
      }
      // algorithm is optional, default is SHA1
      if (otpKey.getAlgorithm() != null) {
        // strip the HMac" part
        if (!otpKey.getAlgorithm().equals("SHA1")) {
          sb.append("&algorithm=").append(otpKey.getAlgorithm());
        }
      }
      // digits is optional, default is 6
      if (totpAuthOptions.getPasswordLength() != 6) {
        sb.append("&digits=").append(totpAuthOptions.getPasswordLength());
      }
      // period is required
      sb.append("&period=").append(totpAuthOptions.getPeriod());

      return String.format(
        "otpauth://totp/%s?%s",
        label,
        sb);

    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  private User createUser(Authenticator authenticator) {
    return User.create(
      new JsonObject()
        .put("otp", "totp")
        .put("auth_attempts", authenticator.getAuthAttempts())
        // amr
        .put("amr", Arrays.asList("mfa", "otp"))
    );
  }
}
