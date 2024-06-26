module io.vertx.auth.htdigest {

  requires transitive io.vertx.auth.common;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.htdigest;

}
