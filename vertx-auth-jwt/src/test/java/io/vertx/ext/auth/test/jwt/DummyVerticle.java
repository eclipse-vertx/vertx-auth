package io.vertx.ext.auth.test.jwt;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

public class DummyVerticle extends AbstractVerticle {

    private static final JWTAuthOptions config = new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setPassword("secret"));

    public void start() {
        System.out.println(this);
        JWTAuth.create(vertx, config);
    }
}
