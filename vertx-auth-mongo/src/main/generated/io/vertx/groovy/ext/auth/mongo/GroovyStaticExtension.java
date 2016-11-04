package io.vertx.groovy.ext.auth.mongo;
public class GroovyStaticExtension {
  public static io.vertx.ext.auth.mongo.MongoAuth create(io.vertx.ext.auth.mongo.MongoAuth j_receiver, io.vertx.ext.mongo.MongoClient mongoClient, java.util.Map<String, Object> config) {
    return io.vertx.lang.groovy.ConversionHelper.wrap(io.vertx.ext.auth.mongo.MongoAuth.create(mongoClient,
      config != null ? io.vertx.lang.groovy.ConversionHelper.toJsonObject(config) : null));
  }
}
