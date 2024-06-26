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
package io.vertx.tests;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.KeyStoreOptions;
import io.vertx.ext.auth.authentication.CredentialValidationException;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.auth.jwt.authorization.JWTAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertNotEquals;

@RunWith(VertxUnitRunner.class)
public class JWTAuthProviderTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private JWTAuth authProvider;

  // {"sub":"Paulo","exp":1747055313,"iat":1431695313,"permissions":["read","write","execute"],"roles":["admin","developer","user"]}
  private static final String JWT_VALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImV4cCI6MTc0NzA1NTMxMywiaWF0IjoxNDMxNjk1MzEzLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiLCJleGVjdXRlIl0sInJvbGVzIjpbImFkbWluIiwiZGV2ZWxvcGVyIiwidXNlciJdfQ.UdA6oYDn9s_k7uogFFg8jvKmq9RgITBnlq4xV6JGsCY";

  // {"sub":"Paulo","iat":1400159434,"exp":1400245834,"roles":["admin","developer","user"],"permissions":["read","write","execute"]}
  private static final String JWT_INVALID = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQYXVsbyIsImlhdCI6MTQwMDE1OTQzNCwiZXhwIjoxNDAwMjQ1ODM0LCJyb2xlcyI6WyJhZG1pbiIsImRldmVsb3BlciIsInVzZXIiXSwicGVybWlzc2lvbnMiOlsicmVhZCIsIndyaXRlIiwiZXhlY3V0ZSJdfQ==.NhHul0OFlmUaatFwNeGBbshVNzac2z_3twEEg57x80s=";

  @Before
  public void setUp() throws Exception {
    authProvider = JWTAuth.create(rule.vertx(), getConfig());
  }

  private JWTAuthOptions getConfig() {
    return new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setType("jceks")
        .setPassword("secret"));
  }

  @Test
  public void testCreateWithoutFailureWhenAliasIsNotSupported() {
    JWTAuthOptions config = getConfig();
    config
      .getKeyStore()
      .putPasswordProtection("foo", "not-so-secret");
    JWTAuth.create(rule.vertx(), config);
    // Just verify no exception is thrown
  }

  @Test
  public void testCreateWithoutFailureWhenAliasDoesNotExist() {
    JWTAuthOptions config = getConfig();
    config
      .getKeyStore()
      .putPasswordProtection("HS384", "not-so-secret");
    JWTAuth.create(rule.vertx(), config);
    // Just verify no exception is thrown
  }

  @Test
  public void testValidJWT(TestContext should) {
    final Async test = should.async();

    TokenCredentials authInfo = new TokenCredentials(JWT_VALID);
    authProvider
      .authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        // assert that the content of the principal is not empty
        should.assertNotNull(res.subject());
        should.assertNotNull(res.principal().getValue("permissions"));
        should.assertNotNull(res.principal().getValue("roles"));

        test.complete();
      });
  }

  @Test
  public void testInValidCredentials(TestContext should) {
    final Async test = should.async();

    authProvider
      .authenticate(new UsernamePasswordCredentials("username", "password"))
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(err -> {
        should.assertNotNull(err);
        should.assertTrue(err instanceof CredentialValidationException);
        test.complete();
      });
  }

  @Test
  public void testInvalidJWT(TestContext should) {
    final Async test = should.async();

    TokenCredentials authInfo = new TokenCredentials(JWT_INVALID);
    authProvider
      .authenticate(authInfo)
      .onSuccess(user -> should.fail())
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testJWTValidPermission(TestContext should) {
    final Async test = should.async();

    TokenCredentials authInfo = new TokenCredentials(JWT_VALID);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        JWTAuthorization.create("permissions").getAuthorizations(user)
          .onComplete(res -> {
            should.assertTrue(res.succeeded());
            should.assertTrue(PermissionBasedAuthorization.create("write").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testJWTInvalidPermission(TestContext should) {
    final Async test = should.async();

    TokenCredentials authInfo = new TokenCredentials(JWT_VALID);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        JWTAuthorization.create("permissions").getAuthorizations(user)
          .onComplete(res -> {
            should.assertTrue(res.succeeded());
            should.assertFalse(PermissionBasedAuthorization.create("drop").match(user));
            test.complete();
          });
      });
  }

  @Test
  public void testGenerateNewToken(TestContext should) {

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
    should.assertNotNull(token);
    should.assertEquals(JWT_VALID, token);
  }

  @Test
  public void testGenerateNewTokenImmutableClaims() {

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    String token0 = authProvider.generateToken(payload.copy().put("permissions", new JsonArray().add("user")));
    String token1 = authProvider.generateToken(payload.copy().put("permissions", new JsonArray().add("admin")));

    assertNotEquals(token0, token1);
  }

  @Test
  public void testTokenWithoutTimestamp(TestContext should) {
    final Async test = should.async();

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
      new JWTOptions().setExpiresInMinutes(5).setNoTimestamp(true));

    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        should.assertTrue(res.attributes().getJsonObject("accessToken").containsKey("exp"));
        should.assertFalse(res.attributes().getJsonObject("accessToken").containsKey("iat"));
        test.complete();
      });
  }

  @Test
  public void testTokenWithTimestamp(TestContext should) {
    final Async test = should.async();

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions());
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        should.assertTrue(res.attributes().getJsonObject("accessToken").containsKey("iat"));
        test.complete();
      });
  }

  @Test
  public void testExpiration(TestContext should) {
    final Async test = should.async();

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
      new JWTOptions().setExpiresInSeconds(1).setNoTimestamp(true));

    should.assertNotNull(token);

    rule.vertx().setTimer(2000L, t -> {
      TokenCredentials authInfo = new TokenCredentials(token);
      authProvider.authenticate(authInfo)
        .onSuccess(user -> should.fail("Should have failed"))
        .onFailure(thr -> {
          should.assertNotNull(thr);
          test.complete();
        });
    });

  }

  @Test
  public void testGoodIssuer(TestContext should) {
    final Async test = should.async();

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions().setIssuer("https://vertx.io"));
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testBadIssuer(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(new JWTOptions().setIssuer("https://vertx.io")));

    JsonObject payload = new JsonObject().put("sub", "Paulo");

    final String token = authProvider.generateToken(payload, new JWTOptions().setIssuer("https://auth0.io"));
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testGoodAudience(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(
      new JWTOptions()
        .addAudience("b")
        .addAudience("d")));

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
      new JWTOptions().addAudience("a").addAudience("b").addAudience("c"));

    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testBadAudience(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(
      new JWTOptions()
        .addAudience("e")
        .addAudience("d")));

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    final String token = authProvider.generateToken(payload,
      new JWTOptions().addAudience("a").addAudience("b").addAudience("c"));

    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testGenerateNewTokenES256(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("es256-keystore.jceks")
        .setType("jceks")
        .setPassword("secret")));

    String token = authProvider.generateToken(new JsonObject().put("sub", "paulo"), new JWTOptions().setAlgorithm("ES256"));
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onComplete(res -> {
        if (res.failed()) {
          res.cause().printStackTrace();
          should.fail();
        }

        should.assertNotNull(res.result());
        test.complete();
      });
  }

  @Test
  public void testGenerateNewTokenWithMacSecret(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addJwk(new JsonObject()
        .put("kty", "oct")
        .put("k", "notasecret"))
    );

    String token = authProvider.generateToken(new JsonObject(), new JWTOptions().setAlgorithm("HS256"));
    should.assertNotNull(token);

    // reverse
    TokenCredentials authInfo = new TokenCredentials(token);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testValidateTokenWithInvalidMacSecret(TestContext should) {
    final Async test = should.async();

    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MDE3ODUyMDZ9.08K_rROcCmKTF1cKfPCli2GQFYIOP8dePxeS1SE4dc8";
    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addJwk(new JsonObject()
        .put("kty", "oct")
        .put("k", Base64.getUrlEncoder().encodeToString("a bad secret".getBytes(StandardCharsets.UTF_8))))
    );
    TokenCredentials authInfo = new TokenCredentials(token);
    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testValidateTokenWithValidMacSecret(TestContext should) {
    final Async test = should.async();

    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MDE3ODUyMDZ9.08K_rROcCmKTF1cKfPCli2GQFYIOP8dePxeS1SE4dc8";
    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addJwk(new JsonObject()
        .put("kty", "oct")
        .put("k", Base64.getUrlEncoder().encodeToString("notasecret".getBytes(StandardCharsets.UTF_8))))
    );
    TokenCredentials authInfo = new TokenCredentials(token);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testGenerateNewTokenForceAlgorithm(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .setKeyStore(new KeyStoreOptions()
        .setPath("keystore.jceks")
        .setType("jceks")
        .setPassword("secret")));

    String token = authProvider.generateToken(new JsonObject(), new JWTOptions().setAlgorithm("RS256"));
    should.assertNotNull(token);

    // reverse
    TokenCredentials authInfo = new TokenCredentials(token);
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testAcceptInvalidJWT(TestContext should) {
    final Async test = should.async();

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
    TokenCredentials authInfo = new TokenCredentials(attackerJWT);
    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(thr -> {
        should.assertNotNull(thr);
        test.complete();
      });
  }

  @Test
  public void testAlgNone(TestContext should) {
    final Async test = should.async();

    JWTAuth authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions());

    JsonObject payload = new JsonObject()
      .put("sub", "UserUnderTest")
      .put("aud", "OrganizationUnderTest")
      .put("iat", 1431695313)
      .put("exp", 1747055313)
      .put("roles", new JsonArray().add("admin").add("developer").add("user"))
      .put("permissions", new JsonArray().add("read").add("write").add("execute"));

    final String token = authProvider.generateToken(payload, new JWTOptions().setSubject("UserUnderTest").setAlgorithm("none"));
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testLeeway(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(new JWTOptions().setLeeway(0)));

    long now = System.currentTimeMillis() / 1000;

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo")
      .put("exp", now);

    String token = authProvider.generateToken(payload);
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);
    // fail because exp is <= to now
    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(t -> test.complete());
  }

  @Test
  public void testLeeway2(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(new JWTOptions().setLeeway(0)));

    long now = (System.currentTimeMillis() / 1000) + 2;

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo")
      .put("iat", now);

    String token = authProvider.generateToken(payload);
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);
    // fail because iat is > now (clock drifted 2 sec)
    authProvider.authenticate(authInfo)
      .onSuccess(user -> should.fail("Should have failed"))
      .onFailure(t -> test.complete());
  }

  @Test
  public void testLeeway3(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(new JWTOptions().setLeeway(5)));

    long now = System.currentTimeMillis() / 1000;

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo")
      .put("exp", now)
      .put("iat", now);

    String token = authProvider.generateToken(payload);
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);
    // fail because exp is <= to now
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(t -> test.complete());
  }

  @Test
  public void testLeeway4(TestContext should) {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), getConfig().setJWTOptions(new JWTOptions().setLeeway(5)));

    long now = (System.currentTimeMillis() / 1000) + 2;

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo")
      .put("iat", now);

    String token = authProvider.generateToken(payload);
    should.assertNotNull(token);

    TokenCredentials authInfo = new TokenCredentials(token);
    // pass because iat is > now (clock drifted 2 sec) and we have a leeway of 5sec
    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(t -> test.complete());
  }

  @Test
  public void testJWKShouldNotCrash() {
    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions().addJwk(
      new JsonObject()
        .put("kty", "RSA")
        .put("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
        .put("e", "AQAB")
        .put("alg", "RS256")
        .put("kid", "2011-04-29")));

  }

  @Test
  public void testValidateTokenWithIgnoreExpired(TestContext should) throws InterruptedException {
    final Async test = should.async();

    authProvider = JWTAuth.create(rule.vertx(), new JWTAuthOptions()
      .addJwk(new JsonObject()
        .put("kty", "oct")
        .put("k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"))
      .setJWTOptions(new JWTOptions()
        .setIgnoreExpiration(true)));

    String token = authProvider
      .generateToken(
        new JsonObject(),
        new JWTOptions()
          .setExpiresInSeconds(1)
          .setSubject("subject")
          .setAlgorithm("HS256"));

    // force a sleep to invalidate the token
    Thread.sleep(1001);

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        test.complete();
      });
  }

  @Test
  public void testGenerateClaimsAndCheck(TestContext should) {
    final Async test = should.async();

    JsonObject payload = new JsonObject()
      .put("sub", "Paulo");

    String token = authProvider.generateToken(payload.copy().put("permissions", new JsonArray().add("user")));

    TokenCredentials authInfo = new TokenCredentials(token);

    authProvider.authenticate(authInfo)
      .onFailure(should::fail)
      .onSuccess(res -> {
        should.assertNotNull(res);
        JWTAuthorization.create("permissions").getAuthorizations(res)
          .onComplete(permissions -> {
            should.assertTrue(permissions.succeeded());
            should.assertTrue(PermissionBasedAuthorization.create("user").match(res));
            test.complete();
          });
      });
  }

}
