package io.vertx.ext.auth.jdbc;

import io.vertx.core.VertxException;

public class AuthFailedException extends VertxException {
  public AuthFailedException(String message) {
    super(message);
  }

  public AuthFailedException(Throwable cause) {
    super(cause);
  }
}
