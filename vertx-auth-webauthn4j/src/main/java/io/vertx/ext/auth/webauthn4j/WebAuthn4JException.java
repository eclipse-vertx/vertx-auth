package io.vertx.ext.auth.webauthn4j;

import io.vertx.codegen.annotations.GenIgnore;

@SuppressWarnings("serial")
@GenIgnore
public class WebAuthn4JException extends RuntimeException {
  public WebAuthn4JException(String message) {
    super(message);
  }
  public WebAuthn4JException(String message, Throwable cause) {
    super(message, cause);
  }
  public WebAuthn4JException(Throwable cause) {
    super(cause);
  }
}
