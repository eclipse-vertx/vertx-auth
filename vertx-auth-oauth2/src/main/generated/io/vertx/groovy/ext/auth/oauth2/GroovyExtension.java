package io.vertx.groovy.ext.auth.oauth2;
public class GroovyExtension {
  public static java.lang.String authorizeURL(io.vertx.ext.auth.oauth2.OAuth2Auth j_receiver, java.util.Map<String, Object> params) {
    return j_receiver.authorizeURL(params != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(params) : null);
  }
  public static void getToken(io.vertx.ext.auth.oauth2.OAuth2Auth j_receiver, java.util.Map<String, Object> params, io.vertx.core.Handler<io.vertx.core.AsyncResult<io.vertx.ext.auth.oauth2.AccessToken>> handler) {
    j_receiver.getToken(params != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(params) : null,
      handler != null ? new io.vertx.core.Handler<io.vertx.core.AsyncResult<io.vertx.ext.auth.oauth2.AccessToken>>() {
      public void handle(io.vertx.core.AsyncResult<io.vertx.ext.auth.oauth2.AccessToken> ar) {
        handler.handle(ar.map(event -> io.vertx.lang.groovy.ConversionHelper.wrap(event)));
      }
    } : null);
  }
  public static io.vertx.ext.auth.oauth2.OAuth2Auth api(io.vertx.ext.auth.oauth2.OAuth2Auth j_receiver, io.vertx.core.http.HttpMethod method, java.lang.String path, java.util.Map<String, Object> params, io.vertx.core.Handler<io.vertx.core.AsyncResult<java.util.Map<String, Object>>> handler) {
    io.vertx.lang.groovy.ConversionHelper.wrap(j_receiver.api(method,
      path,
      params != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(params) : null,
      handler != null ? new io.vertx.core.Handler<io.vertx.core.AsyncResult<io.vertx.core.json.JsonObject>>() {
      public void handle(io.vertx.core.AsyncResult<io.vertx.core.json.JsonObject> ar) {
        handler.handle(ar.map(event -> io.vertx.lang.groovy.ConversionHelper.fromJsonObject(event)));
      }
    } : null));
    return j_receiver;
  }
}
