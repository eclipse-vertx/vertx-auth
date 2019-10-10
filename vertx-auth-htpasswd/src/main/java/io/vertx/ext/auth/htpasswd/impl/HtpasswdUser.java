package io.vertx.ext.auth.htpasswd.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

/**
 * @author Neven Radovanović
 */
public class HtpasswdUser extends AbstractUser {

  private final String username;

  HtpasswdUser(String username) {
    this.username = username;
  }

  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    resultHandler.handle(Future.succeededFuture(false));
  }

  @Override
  public JsonObject principal() {
    return new JsonObject()
      .put("username", username);
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {

  }
}
