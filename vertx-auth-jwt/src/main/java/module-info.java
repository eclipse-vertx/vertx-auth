module io.vertx.auth.jwt {

  requires transitive io.vertx.auth.common;

  requires io.vertx.core.logging;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.jwt;
  exports io.vertx.ext.auth.jwt.authorization;

  exports io.vertx.ext.auth.jwt.impl to io.vertx.tests;

}
