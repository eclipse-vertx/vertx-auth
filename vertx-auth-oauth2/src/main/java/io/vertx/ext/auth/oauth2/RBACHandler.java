package io.vertx.ext.auth.oauth2;

import io.vertx.codegen.annotations.VertxGen;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

@VertxGen
@FunctionalInterface
public interface RBACHandler {

  void isAuthorized(OAuth2User user, String authority, Handler<AsyncResult<Boolean>> handler);
}
