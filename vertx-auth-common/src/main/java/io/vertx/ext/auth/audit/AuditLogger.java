package io.vertx.ext.auth.audit;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.ext.auth.audit.impl.SecurityLoggerImpl;
import io.vertx.ext.auth.impl.jose.JWK;

@VertxGen
public interface AuditLogger {

  static AuditLogger instance() {
    return SecurityLoggerImpl.INSTANCE;
  }

  static AuditLogger init(JWK jwk) {
    SecurityLoggerImpl.init(jwk);
    return instance();
  }

  default void succeeded(Marker marker) {
    succeeded(marker, null);
  }

  void succeeded(Marker marker, StructuredData data);

  default void failed(Marker marker, Throwable cause) {
    failed(marker, null, cause);
  }

  void failed(Marker marker, StructuredData data, Throwable cause);

  default <T> Handler<AsyncResult<T>> handle(Marker marker) {
    return handle(marker, null);
  }

  <T> Handler<AsyncResult<T>> handle(Marker marker, StructuredData data);
}
