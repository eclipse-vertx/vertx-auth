/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */
package io.vertx.ext.auth.test.jwt;

import io.vertx.core.AsyncResult;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

public class JWTAuthProviderTest extends VertxTestBase {

  protected JWTAuth authProvider;

  // {"sub":"Paulo","iat":1431695313,"exp":1747055313,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_VALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQzMTY5NTMxMywiZXhwIjoxNzQ3MDU1MzEzLCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.D6FLewkLz4lmCsUYLQS82x6QMjgSaMg0ROYXiKXorgo=";

  // {"sub":"Paulo","iat":1400159434,"exp":1400245834,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_INVALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQwMDE1OTQzNCwiZXhwIjoxNDAwMjQ1ODM0LCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.NhHul0OFlmUaatFwNeGBbshVNzac2z_3twEEg57x80s=";

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = JWTAuth.create(vertx, getConfig());
  }

  protected JsonObject getConfig() {
    return new JsonObject().put("keyStore", new JsonObject()
        .put("path", "keystore.jceks")
        .put("type", "jceks")
        .put("password", "secret"));
  }

  @Test
  public void testValidJWT() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testInvalidJWT() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_INVALID);
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testJWTValidPermission() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      user.isAuthorised("write", onSuccess(res -> {
        assertNotNull(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testJWTInvalidPermission() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      user.isAuthorised("drop", onSuccess(hasPermission -> {
        assertFalse(hasPermission);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testGenerateNewToken() {

    JsonObject payload = new JsonObject()
        .put("sub", "Paulo")
        .put("iat", 1431695313)
        .put("exp", 1747055313)
        .put("roles", new JsonArray()
            .add("admin")
            .add("developer")
            .add("user"))
        .put("permissions", new JsonArray()
                .add("read")
                .add("write")
                .add("execute"));

    String token = authProvider.generateToken(payload, new JWTOptions().setSubject("Paulo"));
    assertNotNull(token);
    assertEquals(JWT_VALID, token);
  }

  @Test
  public void testTokenWithoutTimestamp() {
    JsonObject payload = new JsonObject()
        .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
        new JWTOptions().setExpiresInMinutes(5L).setNoTimestamp(true));

    assertNotNull(token);

    JsonObject authInfo = new JsonObject().put("jwt", token);

    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      assertTrue(res.principal().containsKey("exp"));
      assertFalse(res.principal().containsKey("iat"));
      testComplete();
    }));

    await();
  }

  @Test
  public void testTokenWithTimestamp() {
    JsonObject payload = new JsonObject()
        .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions());
    assertNotNull(token);

    JsonObject authInfo = new JsonObject().put("jwt", token);
    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      assertTrue(res.principal().containsKey("iat"));
      testComplete();
    }));
    await();
  }

  @Test
  public void testExpiration() {
    JsonObject payload = new JsonObject()
            .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
        new JWTOptions().setExpiresInMinutes(-5L).setNoTimestamp(true));

    assertNotNull(token);

    JsonObject authInfo = new JsonObject().put("jwt", token);
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testGoodIssuer() {
    JsonObject payload = new JsonObject()
            .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions().setIssuer("https://vertx.io"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
        .put("jwt", token)
        .put("options", new JsonObject()
            .put("issuer", "https://vertx.io"));

    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testBadIssuer() {
    JsonObject payload = new JsonObject().put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions().setIssuer("https://auth0.io"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
        .put("jwt", token)
        .put("options", new JsonObject()
             .put("issuer", "https://vertx.io"));

    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testGoodAudience() {
    JsonObject payload = new JsonObject()
            .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
        new JWTOptions().addAudience("a").addAudience("b").addAudience("c"));

    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
        .put("jwt", token)
        .put("options", new JsonObject()
             .put("audience", new JsonArray().add("b").add("d")));

    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testBadAudience() {
    JsonObject payload = new JsonObject()
            .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
        new JWTOptions().addAudience("a").addAudience("b").addAudience("c"));

    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
        .put("jwt", token)
        .put("options", new JsonObject()
             .put("audience", new JsonArray().add("e").add("d")));

    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testGenerateNewTokenES256() {
    authProvider = JWTAuth.create(vertx, new JsonObject().put("keyStore", new JsonObject()
        .put("path", "es256-keystore.jceks")
        .put("type", "jceks")
        .put("password", "secret")));

    String token = authProvider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions().setAlgorithm("ES256"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
        .put("jwt", token);

    authProvider.authenticate(authInfo, res -> {
        if (res.failed()) {
          res.cause().printStackTrace();
          fail();
        }
        System.out.println(res.result());
      testComplete();
    });
    await();
  }
}