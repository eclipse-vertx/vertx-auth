package io.vertx.tests;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

public class DummyVerticle extends AbstractVerticle {

  private static final JWTAuthOptions config = new JWTAuthOptions()
    .setKeyStore(new KeyStoreOptions()
      .setPath("keystore.jceks")
      .setType("jceks")
      .setPassword("secret"));

  public void start() {
    JWTAuth.create(vertx, config);
  }
}
