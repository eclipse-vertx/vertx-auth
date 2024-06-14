package io.vertx.ext.auth.audit;

import io.vertx.codegen.annotations.Fluent;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.auth.user.User;
import io.vertx.ext.auth.audit.impl.SecurityAuditNOOP;
import io.vertx.ext.auth.audit.impl.SecurityAuditLogger;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authorization.Authorization;

@VertxGen
public interface SecurityAudit {

  static SecurityAudit create() {
    if (SecurityAuditLogger.isEnabled()) {
      return new SecurityAuditLogger();
    }
    // no logging
    return SecurityAuditNOOP.INSTANCE;
  }

  @Fluent
  SecurityAudit source(SocketAddress address);

  @Fluent
  SecurityAudit destination(SocketAddress address);

  SecurityAudit resource(HttpVersion version, HttpMethod method, String path);

  @Fluent
  SecurityAudit resource(String resource);

  @Fluent
  SecurityAudit credentials(Credentials credentials);

  @Fluent
  SecurityAudit user(User user);

  @Fluent
  SecurityAudit authorization(Authorization authorization);

  @Fluent
  SecurityAudit status(int status);

  void audit(Marker marker, boolean success);

  default <T> Handler<AsyncResult<T>> auditHandlerFor(Marker marker) {
    return event -> audit(marker, event.succeeded());
  }
}
