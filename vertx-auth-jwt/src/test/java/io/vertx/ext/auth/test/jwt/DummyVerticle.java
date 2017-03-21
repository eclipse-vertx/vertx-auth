package io.vertx.ext.auth.test.jwt;

import io.vertx.core.AbstractVerticle;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.JWTKeyStoreOptions;

public class DummyVerticle extends AbstractVerticle {

    private static final JWTAuthOptions config = new JWTAuthOptions()
      .setKeyStore(new JWTKeyStoreOptions()
        .setPath("keystore.jceks")
        .setPassword("secret"));

    public void start() {
        System.out.println(this);
        JWTAuth.create(vertx, config);
    }
}
