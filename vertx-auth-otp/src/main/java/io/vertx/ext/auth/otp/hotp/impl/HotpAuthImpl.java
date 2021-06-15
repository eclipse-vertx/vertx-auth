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

package io.vertx.ext.auth.otp.hotp.impl;

import com.eatthepath.otp.HmacOneTimePasswordGenerator;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.otp.hotp.HotpAuth;
import io.vertx.ext.auth.otp.hotp.HotpAuthOptions;
import io.vertx.ext.auth.otp.hotp.HotpCredentials;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class HotpAuthImpl implements HotpAuth {

  private final Base32 base32 = new Base32(false);

  private final HotpAuthOptions hotpAuthOptions;

  private final ConcurrentMap<String, User> hotpUserMap;

  private final HmacOneTimePasswordGenerator hotp;

  public HotpAuthImpl(HotpAuthOptions hotpAuthOptions) {
    if (hotpAuthOptions == null) {
      throw new IllegalArgumentException("hotpAuthOptions cannot null");
    }
    this.hotpAuthOptions = hotpAuthOptions;

    hotpUserMap = new ConcurrentHashMap<>();
    try {
      hotp = new HmacOneTimePasswordGenerator(6);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void authenticate(JsonObject credentials, Handler<AsyncResult<User>> resultHandler) {
    authenticate(new HotpCredentials(credentials), resultHandler);
  }

  @Override
  public void authenticate(Credentials credentials, Handler<AsyncResult<User>> resultHandler) {
    try {
      HotpCredentials authInfo = (HotpCredentials) credentials;
      authInfo.checkValid(hotpAuthOptions);

      User user = hotpUserMap.get(authInfo.getIdentifier());
      if (user == null) {
        resultHandler.handle(Future.failedFuture("user is not found"));
        return;
      }

      validateUser(user);

      long counter = user.principal().getLong("counter");
      String key = user.principal().getString("key");

      SecretKeySpec secretKeySpec = new SecretKeySpec(base32.decode(key), HmacOneTimePasswordGenerator.HOTP_HMAC_ALGORITHM);
      counter = ++counter;
      Long authAttempts = user.attributes().getLong("auth_attempts");
      authAttempts = authAttempts != null ? ++authAttempts : 1;
      user.attributes().put("auth_attempts", authAttempts);
      String oneTimePassword;
      try {
        oneTimePassword = hotp.generateOneTimePasswordString(secretKeySpec, counter, Locale.ENGLISH);
      } catch (InvalidKeyException e) {
        resultHandler.handle(Future.failedFuture(e));
        return;
      }

      if (oneTimePassword.equals(authInfo.getCode())) {
        user.attributes().put("counter", counter);
        hotpUserMap.remove(authInfo.getIdentifier());
        resultHandler.handle(Future.succeededFuture(user));
        return;
      }

      if (hotpAuthOptions.isUsingAttemptsLimit() && authAttempts >= hotpAuthOptions.getAuthAttemptsLimit()) {
        hotpUserMap.remove(authInfo.getIdentifier());
      } else if (hotpAuthOptions.isUsingResynchronization()) {
        for (int i = 0; i < hotpAuthOptions.getLookAheadWindow(); i++) {
          counter = ++counter;

          try {
            oneTimePassword = hotp.generateOneTimePasswordString(secretKeySpec, counter, Locale.ENGLISH);
          } catch (InvalidKeyException e) {
            resultHandler.handle(Future.failedFuture(e));
            return;
          }

          if (oneTimePassword.equals(authInfo.getCode())) {
            user.attributes().put("counter", counter);
            hotpUserMap.remove(authInfo.getIdentifier());
            resultHandler.handle(Future.succeededFuture(user));
            return;
          }
        }
      }
      resultHandler.handle(Future.failedFuture("invalid code"));
    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
    }
  }

  @Override
  public void requestHotp(User user, Handler<AsyncResult<User>> resultHandler) {
    try {
      validateUser(user);
    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
      return;
    }
    hotpUserMap.put(user.principal().getString("identifier"), user);
  }

  @Override
  public void revokeHotp(User user, Handler<AsyncResult<User>> resultHandler) {
    try {
      validateUser(user);
    } catch (RuntimeException e) {
      resultHandler.handle(Future.failedFuture(e));
      return;
    }
    hotpUserMap.remove(user.principal().getString("identifier"));
  }

  private void validateUser(User user) {

    String identifier = user.principal().getString("identifier");
    if (identifier == null || identifier.length() == 0) {
      throw new IllegalStateException("user principal not contain identifier");
    }

    Integer counter = user.principal().getInteger("counter");
    if (counter == null) {
      throw new IllegalStateException("user principal not contain counter");
    } else if (counter < 0) {
      throw new IllegalStateException("counter has negative value");
    }

    String key = user.principal().getString("key");
    if (key == null || key.length() == 0) {
      throw new IllegalStateException("user principal not contain key");
    }
  }

  public HotpAuthOptions getHotpAuthOptions() {
    return hotpAuthOptions;
  }
}
