package io.vertx.ext.auth.oauth2.impl;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.impl.UserImpl;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2Response;

public class AccessTokenImpl extends UserImpl implements AccessToken {

  private static final Logger LOG = LoggerFactory.getLogger(AccessTokenImpl.class);

  private OAuth2Auth oAuth2Auth;

  // required for clustering
  public AccessTokenImpl() {
    super();
  }

  public AccessTokenImpl(JsonObject principal, OAuth2Auth oAuth2Auth) {
    super(principal);
    this.oAuth2Auth = oAuth2Auth;
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    this.oAuth2Auth = (OAuth2Auth) authProvider;
  }

  @Override
  public boolean isScopeGranted() {
    return false;
  }

  @Override
  public JsonObject accessToken() {
    return principal().getJsonObject("accessToken");
  }

  @Override
  public JsonObject idToken() {
    return principal().getJsonObject("idToken");
  }

  @Override
  public String opaqueAccessToken() {
    return principal().getString("access_token");
  }

  @Override
  public String opaqueRefreshToken() {
    return principal().getString("refresh_token");
  }

  @Override
  public String opaqueIdToken() {
    return principal().getString("id_token");
  }

  @Override
  public String tokenType() {
    return principal().getString("token_type");
  }

  @Override
  public AccessToken setTrustJWT(boolean trust) {
    LOG.warn("This operation is not supported.");
    return this;
  }

  @Override
  public AccessToken refresh(Handler<AsyncResult<Void>> callback) {
    oAuth2Auth.refresh(this, refresh -> {
      if (refresh.failed()) {
        callback.handle(Future.failedFuture(refresh.cause()));
      } else {
        User user = refresh.result();
        // merge properties
        attributes().mergeIn(user.attributes());
        principal().mergeIn(user.principal());
        callback.handle(Future.succeededFuture());
      }
    });
    return this;
  }

  @Override
  public AccessToken revoke(String token_type, Handler<AsyncResult<Void>> callback) {
    oAuth2Auth.revoke(this, token_type, revoke -> {
      if (revoke.failed()) {
        callback.handle(Future.failedFuture(revoke.cause()));
      } else {
        // clear properties
        principal().remove(token_type);
        callback.handle(Future.succeededFuture());
      }
    });
    return this;
  }

  @Override
  public AccessToken logout(Handler<AsyncResult<Void>> callback) {
    LOG.warn("This operation is not supported, this was a Keycloak specific feature not a standard");
    callback.handle(Future.failedFuture(new UnsupportedOperationException()));
    return this;
  }

  @Override
  public AccessToken introspect(Handler<AsyncResult<Void>> callback) {
    LOG.warn("This operation is not supported, authenticate the user instead");
    callback.handle(Future.failedFuture(new UnsupportedOperationException()));
    return this;
  }

  @Override
  public AccessToken introspect(String tokenType, Handler<AsyncResult<Void>> callback) {
    LOG.warn("This operation is not supported, authenticate the user instead");
    callback.handle(Future.failedFuture(new UnsupportedOperationException()));
    return this;
  }

  @Override
  public AccessToken userInfo(Handler<AsyncResult<JsonObject>> callback) {
    oAuth2Auth.userInfo(this, callback);
    return this;
  }

  @Override
  public AccessToken fetch(HttpMethod method, String resource, JsonObject headers, Buffer payload, Handler<AsyncResult<OAuth2Response>> callback) {
    LOG.warn("This operation is not supported, use a WebClient instead");
    callback.handle(Future.failedFuture(new UnsupportedOperationException()));
    return this;
  }
}
