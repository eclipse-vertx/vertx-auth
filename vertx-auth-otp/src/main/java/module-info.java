module io.vertx.auth.otp {

  requires transitive io.vertx.auth.common;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;

  exports io.vertx.ext.auth.otp;
  exports io.vertx.ext.auth.otp.hotp;
  exports io.vertx.ext.auth.otp.totp;

}
