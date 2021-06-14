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

package io.vertx.ext.auth.otp.utils;

import java.net.URI;

public class AuthenticatorUriGenerator {

  private static final String HOTP_GOOGLE_AUTH_URI_TEMPLATE = "otpauth://hotp/%s:%s?secret=%s&issuer=%s";

  public static URI generateHotpUri(OtpKey otpKey, String label, String user, String issuer) {
    String uri = String.format(HOTP_GOOGLE_AUTH_URI_TEMPLATE, label, user, otpKey.getBase32(), issuer);
    return URI.create(uri);
  }
}
