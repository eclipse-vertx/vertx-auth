package io.vertx.groovy.ext.auth;
public class GroovyExtension {
  public static void authenticate(io.vertx.ext.auth.AuthProvider j_receiver, java.util.Map<String, Object> authInfo, io.vertx.core.Handler<io.vertx.core.AsyncResult<io.vertx.ext.auth.User>> resultHandler) {
    j_receiver.authenticate(authInfo != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(authInfo) : null,
      resultHandler != null ? new io.vertx.core.Handler<io.vertx.core.AsyncResult<io.vertx.ext.auth.User>>() {
      public void handle(io.vertx.core.AsyncResult<io.vertx.ext.auth.User> ar) {
        resultHandler.handle(ar.map(event -> io.vertx.lang.groovy.ConversionHelper.wrap(event)));
      }
    } : null);
  }
  public static java.util.Map<String, Object> principal(io.vertx.ext.auth.User j_receiver) {
    return io.vertx.lang.groovy.ConversionHelper.fromJsonObject(j_receiver.principal());
  }
}
