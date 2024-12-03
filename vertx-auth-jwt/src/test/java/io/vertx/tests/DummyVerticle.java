package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.core.VerticleBase;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

public class DummyVerticle extends VerticleBase {

  private static final JWTAuthOptions config = new JWTAuthOptions()
    .setKeyStore(new KeyStoreOptions()
      .setPath("keystore.jceks")
      .setType("jceks")
      .setPassword("secret"));

  public Future<?> start() throws Exception {
    JWTAuth.create(vertx, config);
    return super.start();
  }
}
