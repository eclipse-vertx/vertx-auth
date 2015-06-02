package io.vertx.ext.auth.mongo;

/**
 * Signals an error inside the authentication process <br>
 * 
 * @author mremme
 */
public class AuthenticationException extends RuntimeException {

  public AuthenticationException() {
  }

  public AuthenticationException(String message) {
    super(message);
  }

  public AuthenticationException(Throwable cause) {
    super(cause);
  }

  public AuthenticationException(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthenticationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
