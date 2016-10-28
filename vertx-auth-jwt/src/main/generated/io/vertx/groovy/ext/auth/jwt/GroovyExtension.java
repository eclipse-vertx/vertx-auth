package io.vertx.groovy.ext.auth.jwt;
public class GroovyExtension {
  public static java.lang.String generateToken(io.vertx.ext.auth.jwt.JWTAuth j_receiver, java.util.Map<String, Object> claims, java.util.Map<String, Object> options) {
    return j_receiver.generateToken(claims != null ? io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(claims) : null,
      options != null ? new io.vertx.ext.auth.jwt.JWTOptions(io.vertx.lang.groovy.RetroCompatExtension.toJsonObject(options)) : null);
  }
}
