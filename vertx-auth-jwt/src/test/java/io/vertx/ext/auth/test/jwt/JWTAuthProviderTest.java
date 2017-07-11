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
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertNotEquals;

public class JWTAuthProviderTest extends VertxTestBase {

  private JWTAuth authProvider;

  // {"sub":"Paulo","exp":1747055313,"iat":1431695313,"permissions":["read","write","execute"],"roles":["admin","developer","user"]}
  private static final String JWT_VALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImV4cCI6MTc0NzA1NTMxMywiaWF0IjoxNDMxNjk1MzEzLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiLCJleGVjdXRlIl0sInJvbGVzIjpbImFkbWluIiwiZGV2ZWxvcGVyIiwidXNlciJdfQ.UdA6oYDn9s_k7uogFFg8jvKmq9RgITBnlq4xV6JGsCY";

  // {"sub":"Paulo","iat":1400159434,"exp":1400245834,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_INVALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQwMDE1OTQzNCwiZXhwIjoxNDAwMjQ1ODM0LCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.NhHul0OFlmUaatFwNeGBbshVNzac2z_3twEEg57x80s=";

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = JWTAuth.create(vertx, getConfig());
  }

  private JWTAuthOptions getConfig() {
    return new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setType("jceks")
        .setPassword("secret"));
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
      .put("exp", 1747055313)
      .put("iat", 1431695313)
      .put("permissions", new JsonArray()
        .add("read")
        .add("write")
        .add("execute"))
      .put("roles", new JsonArray()
        .add("admin")
        .add("developer")
        .add("user"));

    String token = authProvider.generateToken(payload, new JWTOptions().setSubject("Paulo"));
    assertNotNull(token);
    assertEquals(JWT_VALID, token);
  }

  @Test
  public void testGenerateNewTokenImmutableClaims() {

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    String token0 = authProvider.generateToken(payload, new JWTOptions().addPermission("user"));
    String token1 = authProvider.generateToken(payload, new JWTOptions().addPermission("admin"));

    assertNotEquals(token0, token1);
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

    authProvider = JWTAuth.create(vertx, getConfig().setIssuer("https://vertx.io"));

    JsonObject payload = new JsonObject().put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions().setIssuer("https://auth0.io"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
      .put("jwt", token);

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

    authProvider = JWTAuth.create(vertx, getConfig()
      .addAudience("e")
      .addAudience("d"));

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
      new JWTOptions().addAudience("a").addAudience("b").addAudience("c"));

    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
      .put("jwt", token);

    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testGenerateNewTokenES256() {
    authProvider = JWTAuth.create(vertx, new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("es256-keystore.jceks")
        .setPassword("secret")));

    String token = authProvider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions().setAlgorithm("ES256"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject()
      .put("jwt", token);

    authProvider.authenticate(authInfo, res -> {
      if (res.failed()) {
        res.cause().printStackTrace();
        fail();
      }

      assertNotNull(res.result());
      testComplete();
    });
    await();
  }

  @Test
  public void testGenerateNewTokenForceAlgorithm() {
    authProvider = JWTAuth.create(vertx, new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("gce.jks")
        .setType("jks")
        .setPassword("notasecret")));

    String token = authProvider.generateToken(new JsonObject(), new JWTOptions().setAlgorithm("RS256"));
    assertNotNull(token);

    // reverse
    JsonObject authInfo = new JsonObject().put("jwt", token);
    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAcceptInvalidJWT() {
    String[] segments = JWT_INVALID.split("\\.");
    // All segment should be base64
    String headerSeg = segments[0];

    // change alg to none
    JsonObject headerJson = new JsonObject(new String(Base64.getUrlDecoder().decode(headerSeg.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8));
    headerJson.put("alg", "none");
    headerSeg = Base64.getUrlEncoder().encodeToString(headerJson.encode().getBytes(StandardCharsets.UTF_8));

    // fix time exp
    String payloadSeg = segments[1];
    JsonObject bodyJson = new JsonObject(new String(Base64.getUrlDecoder().decode(payloadSeg.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8));
    bodyJson.put("exp", System.currentTimeMillis() + 10000);
    payloadSeg = Base64.getUrlEncoder().encodeToString(headerJson.encode().getBytes(StandardCharsets.UTF_8));

    String signatureSeg = segments[2];

    // build attack token
    String attackerJWT = headerSeg + "." + payloadSeg + "." + signatureSeg;
    JsonObject authInfo = new JsonObject().put("jwt", attackerJWT);
    authProvider.authenticate(authInfo, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAlgNone() {

    JWTAuth authProvider = JWTAuth.create(vertx, new JWTAuthOptions());

    JsonObject payload = new JsonObject()
      .put("sub", "UserUnderTest")
      .put("aud", "OrganizationUnderTest")
      .put("iat", 1431695313)
      .put("exp", 1747055313)
      .put("roles", new JsonArray().add("admin").add("developer").add("user"))
      .put("permissions", new JsonArray().add("read").add("write").add("execute"));

    final String token = authProvider.generateToken(payload, new JWTOptions().setSubject("UserUnderTest").setAlgorithm("none"));
    assertNotNull(token);

    JsonObject authInfo = new JsonObject().put("jwt", token);

    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }
}
