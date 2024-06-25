package io.vertx.ext.auth.audit.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.audit.Marker;
import io.vertx.ext.auth.audit.SecurityAudit;
import io.vertx.ext.auth.authentication.Credentials;
import io.vertx.ext.auth.authorization.Authorization;

public final class SecurityAuditNOOP implements SecurityAudit {

  private static final Handler NOOP = event -> {};

  public static final SecurityAudit INSTANCE = new SecurityAuditNOOP();

  private SecurityAuditNOOP() {
  }

  @Override
  public SecurityAudit source(SocketAddress address) {
    return this;
  }

  @Override
  public SecurityAudit destination(SocketAddress address) {
    return this;
  }

  @Override
  public SecurityAudit resource(HttpVersion version, HttpMethod method, String path) {
    return this;
  }

  @Override
  public SecurityAudit resource(String resource) {
    return this;
  }

  @Override
  public SecurityAudit credentials(Credentials credentials) {
    return this;
  }

  @Override
  public SecurityAudit user(User user) {
    return this;
  }

  @Override
  public SecurityAudit authorization(Authorization authorization) {
    return this;
  }

  @Override
  public SecurityAudit status(int status) {
    return this;
  }

  @Override
  public void audit(Marker marker, boolean success) {

  }

  @Override
  public <T> Handler<AsyncResult<T>> auditHandlerFor(Marker marker) {
    return (Handler) NOOP;
  }
}
