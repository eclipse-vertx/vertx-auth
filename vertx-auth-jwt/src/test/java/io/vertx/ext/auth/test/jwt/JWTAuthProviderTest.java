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

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class JWTAuthProviderTest extends VertxTestBase {

  protected JWTAuth authProvider;

  // {"sub":"Paulo","iat":1431695313,"exp":1747055313,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_VALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQzMTY5NTMxMywiZXhwIjoxNzQ3MDU1MzEzLCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.D6FLewkLz4lmCsUYLQS82x6QMjgSaMg0ROYXiKXorgo=";

  // {"sub":"Paulo","iat":1400159434,"exp":1400245834,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_INVALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQwMDE1OTQzNCwiZXhwIjoxNDAwMjQ1ODM0LCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.NhHul0OFlmUaatFwNeGBbshVNzac2z_3twEEg57x80s=";

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = JWTAuth.create(getConfig());
  }

  protected JsonObject getConfig() {
    return new JsonObject()
        .put("keyStoreType", "jceks")
        .put("keyStoreURI", "classpath:///keystore.jceks")
        .put("keyStorePassword", "secret");
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
  public void testJWTValidRole() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      user.hasRole("developer", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testJWTInvalidRole() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      user.hasRole("root", onSuccess(hasRole -> {
        assertFalse(hasRole);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testJWTValidPermission() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      user.isPermitted("write", onSuccess(res -> {
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

      user.isPermitted("drop", onSuccess(hasPermission -> {
        assertFalse(hasPermission);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testJWTValidRoles() {
    JsonObject authInfo = new JsonObject().put("jwt", JWT_VALID);
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);

      Set<String> roles = new HashSet<>();

      roles.add("developer");
      roles.add("user");

      user.hasRoles(roles, onSuccess(res -> {
        assertNotNull(res);
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
        new JWTOptions().setExpiresInMinutes(5).setNoTimestamp(true));

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
        new JWTOptions().setExpiresInMinutes(-5).setNoTimestamp(true));

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
}