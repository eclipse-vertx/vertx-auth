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
import io.vertx.codegen.annotations.Nullable;
import io.vertx.codegen.annotations.VertxGen;

/**
 * AuthenticatorTransport
 * https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
 */
@VertxGen
public enum AuthenticatorTransport {
  USB("usb"),
  NFC("nfc"),
  BLE("ble"),
  HYBRID("hybrid"),
  INTERNAL("internal");


  private final String value;

  AuthenticatorTransport(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }

  @Nullable
  @GenIgnore(GenIgnore.PERMITTED_TYPE)
  public static AuthenticatorTransport of(String string) {
    for (AuthenticatorTransport el : values()) {
      if (el.toString().equals(string)) {
        return el;
      }
    }
    return null;
  }
}
