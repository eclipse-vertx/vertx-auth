package io.vertx.ext.auth;

import io.vertx.codegen.annotations.ProxyGen;
import io.vertx.codegen.annotations.ProxyIgnore;
import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.serviceproxy.ProxyHelper;


/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
@VertxGen
@ProxyGen
public interface AuthService {

  static AuthService create(Vertx vertx, JsonObject config) {
    return new AuthServiceImpl(vertx, config);
  }

  static AuthService createEventBusProxy(Vertx vertx, String address) {
    return ProxyHelper.createProxy(AuthService.class, vertx, address);
  }

  void login(JsonObject credentials, Handler<AsyncResult<Void>> resultHandler);

  void hasRole(String subject, Handler<AsyncResult<Boolean>> resultHandler);

  void hasPermission(String permission, Handler<AsyncResult<Boolean>> resultHandler);

  @ProxyIgnore
  void start();

  @ProxyIgnore
  void stop();

}
