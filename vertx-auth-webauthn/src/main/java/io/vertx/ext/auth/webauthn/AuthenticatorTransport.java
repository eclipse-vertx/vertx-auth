package io.vertx.ext.auth.webauthn;

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
  INTERNAL("internal");


  private final String value;

  AuthenticatorTransport(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return value;
  }
}
