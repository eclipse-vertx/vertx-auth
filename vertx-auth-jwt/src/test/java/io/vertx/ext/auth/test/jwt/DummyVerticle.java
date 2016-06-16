package io.vertx.ext.auth.test.jwt;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;

public class DummyVerticle extends AbstractVerticle {

    private static final JsonObject config = new JsonObject().put("keyStore", new JsonObject()
            .put("path", "keystore.jceks")
            .put("type", "jceks")
            .put("password", "secret"));

    public void start() {
        System.out.println(this);
        JWTAuth.create(vertx, config);
    }
}