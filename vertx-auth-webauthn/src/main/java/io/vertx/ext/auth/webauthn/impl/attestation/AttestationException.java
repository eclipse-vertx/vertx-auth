package io.vertx.ext.auth.webauthn.impl.attestation;

public class AttestationException extends RuntimeException {
  public AttestationException(String msg) {
    super(msg);
  }

  public AttestationException(Throwable cause) {
    super(cause);
  }
}
