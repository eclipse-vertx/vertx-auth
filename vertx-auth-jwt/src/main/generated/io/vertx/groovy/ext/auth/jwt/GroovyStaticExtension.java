package io.vertx.groovy.ext.auth.jwt;
public class GroovyStaticExtension {
  public static io.vertx.ext.auth.jwt.JWTAuth create(io.vertx.ext.auth.jwt.JWTAuth j_receiver, io.vertx.core.Vertx vertx, java.util.Map<String, Object> config) {
    return io.vertx.lang.groovy.RetroCompatExtension.wrap(io.vertx.ext.auth.jwt.JWTAuth.create(vertx,
      config != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(config) : null));
  }
}
