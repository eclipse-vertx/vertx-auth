module io.vertx.auth.properties {

  requires transitive io.vertx.auth.common;
  requires io.vertx.core.logging;

  requires static io.vertx.codegen.api;

  exports io.vertx.ext.auth.properties;

}
