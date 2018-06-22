package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.oauth2.OAuth2User;
import io.vertx.ext.auth.oauth2.RBACHandler;

public class OAuth2UserImpl extends AbstractUser implements OAuth2User {

  // state
  private JsonObject principal;
  // runtime
  private transient OAuth2AuthProviderImpl provider;
  private transient RBACHandler rbac;


  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    provider = (OAuth2AuthProviderImpl) authProvider;
    rbac = provider.getRBACHandler();
  }

  @Override
  public JsonObject principal() {
    return principal;
  }

  @Override
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    if (expired()) {
      resultHandler.handle(Future.failedFuture("Expired Token"));
      return;
    }

    rbac.isAuthorized(this, permission, resultHandler);
  }

  @Override
  public void writeToBuffer(Buffer buff) {
    super.writeToBuffer(buff);
    if (principal != null) {
      Buffer buffer = principal.toBuffer();
      buff.appendInt(buffer.length());
      buff.appendBuffer(buff);
    } else {
      buff.appendInt(0);
    }
  }

  @Override
  public int readFromBuffer(int pos, Buffer buff) {
    pos = super.readFromBuffer(pos, buff);
    int len = buff.getInt(pos);
    pos += 4;
    if (len > 0) {
      Buffer buffer = buff.getBuffer(pos, pos + len);
      principal = new JsonObject(buffer);
      pos += len;
    }
    return pos;
  }

  /**
   * Check if the access token is expired or not.
   */
  private boolean expired() {

    long now = System.currentTimeMillis();
    // expires_at is a computed field always in millis
    if (principal.containsKey("expires_at") && principal.getLong("expires_at", 0L) < now) {
      return true;
    }

    // delegate to the JWT lib
    return provider.getJWT().isExpired(accessToken, provider.getConfig().getJWTOptions());
  }

}
