package io.vertx.ext.auth;

import io.vertx.codegen.annotations.GenIgnore;
import io.vertx.codegen.annotations.ProxyGen;
import io.vertx.codegen.annotations.ProxyIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.ext.auth.spi.AuthProvider;
import io.vertx.serviceproxy.ProxyHelper;

import java.util.Set;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
@ProxyGen
public interface AuthService {

  public static final long DEFAULT_LOGIN_TIMEOUT = 5 * 60 * 1000;
  public static final long DEFAULT_REAPER_PERIOD = 5 * 1000;

  @GenIgnore
  static AuthService create(Vertx vertx, AuthProvider provider, JsonObject config) {
    return new AuthServiceImpl(vertx, config, provider, DEFAULT_REAPER_PERIOD);
  }

  @GenIgnore
  static AuthService createFromClassName(Vertx vertx, JsonObject config, String className) {
    return new AuthServiceImpl(vertx, config, className, DEFAULT_REAPER_PERIOD);
  }

  // TODO do we really want to mix json config and typed config (i.e. reaperPeriod) ?
  @GenIgnore
  static AuthService create(Vertx vertx, AuthProvider provider, JsonObject config, long reaperPeriod) {
    return new AuthServiceImpl(vertx, config, provider, reaperPeriod);
  }

  @GenIgnore
  static AuthService createFromClassName(Vertx vertx, JsonObject config, String className, long reaperPeriod) {
    return new AuthServiceImpl(vertx, config, className, reaperPeriod);
  }

  static AuthService createEventBusProxy(Vertx vertx, String address) {
    return ProxyHelper.createProxy(AuthService.class, vertx, address);
  }

  void login(JsonObject credentials, Handler<AsyncResult<String>> resultHandler);

  void loginWithTimeout(JsonObject credentials, long timeout, Handler<AsyncResult<String>> resultHandler);

  void logout(String loginID, Handler<AsyncResult<Void>> resultHandler);

  void refreshLoginSession(String loginID, Handler<AsyncResult<Void>> resultHandler);

  void hasRole(String loginID, String role, Handler<AsyncResult<Boolean>> resultHandler);

  void hasRoles(String loginID, Set<String> roles, Handler<AsyncResult<Boolean>> resultHandler);

  void hasPermission(String loginID, String permission, Handler<AsyncResult<Boolean>> resultHandler);

  void hasPermissions(String loginID, Set<String> permissions, Handler<AsyncResult<Boolean>> resultHandler);

  @ProxyIgnore
  void start();

  @ProxyIgnore
  void stop();

}
