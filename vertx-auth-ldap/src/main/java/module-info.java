module io.vertx.auth.ldap {

  requires transitive io.vertx.auth.common;
  requires java.naming;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;

  exports io.vertx.ext.auth.ldap;

}
