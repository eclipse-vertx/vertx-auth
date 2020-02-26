package io.vertx.ext.auth.jdbc;

import io.vertx.core.VertxException;

public class InvalidAuthInfoException extends VertxException {
  public InvalidAuthInfoException(String message) {
    super(message);
  }
}
