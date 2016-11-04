package io.vertx.groovy.ext.auth.shiro;
public class GroovyStaticExtension {
  public static io.vertx.ext.auth.shiro.ShiroAuth create(io.vertx.ext.auth.shiro.ShiroAuth j_receiver, io.vertx.core.Vertx vertx, io.vertx.ext.auth.shiro.ShiroAuthRealmType realmType, java.util.Map<String, Object> config) {
    return io.vertx.lang.groovy.ConversionHelper.wrap(io.vertx.ext.auth.shiro.ShiroAuth.create(vertx,
      realmType,
      config != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(config) : null));
  }
  public static io.vertx.ext.auth.shiro.ShiroAuth create(io.vertx.ext.auth.shiro.ShiroAuth j_receiver, io.vertx.core.Vertx vertx, java.util.Map<String, Object> options) {
    return io.vertx.lang.groovy.ConversionHelper.wrap(io.vertx.ext.auth.shiro.ShiroAuth.create(vertx,
      options != null ? new io.vertx.ext.auth.shiro.ShiroAuthOptions(io.vertx.lang.groovy.ConversionHelper.toJsonObject(options)) : null));
  }
}
