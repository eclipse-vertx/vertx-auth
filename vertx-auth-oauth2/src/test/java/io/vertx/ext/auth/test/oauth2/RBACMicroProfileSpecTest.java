package io.vertx.ext.auth.test.oauth2;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.impl.OAuth2TokenImpl;
import io.vertx.ext.auth.oauth2.rbac.MicroProfileRBAC;
import io.vertx.ext.jwt.JWK;
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(VertxUnitRunner.class)
public class RBACMicroProfileSpecTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private OAuth2Auth oauth;
  private JWT jwt;

  @Before
  public void setUp(TestContext should) {
    oauth = OAuth2Auth
      .create(
        rule.vertx(),
        new OAuth2ClientOptions()
          .setClientID("dummy-client")
          .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("RS256")
            .setPublicKey(
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmuIC9Qvwoe/3tUpHkcUp\n" +
                "vWmzQqnZtz3HBKbxzc/jBTxUHefJDs88Xjw5nNXhl4tXkHzFRAZHtDnwX074/2oc\n" +
                "PRSWaBjHYXB771af91UPrc9fb4lh3W1a8hmQU6sgKlQVwDnUuePDkCmwKCsuyX0M\n" +
                "wxuwOwEUo4r15NBh/H7FvuHVPnqWK1/kliYtQukF3svQkpZT6/puQ0bEOefROLB+\n" +
                "EAPM0OAaDyknjxCZJenk9FIyC6skOKVaxW7CcE54lIUjS1GKFQc44/+T+u0VKSmh\n" +
                "rRdBNcAhXmdpwjLoDTy/I8z+uqkKitdEVczCdleNqeb6b1kjPWS3VbLXxY/LIYlz\n" +
                "uQIDAQAB")
          )
      )
      .rbacHandler(MicroProfileRBAC.create());

    should.assertNotNull(oauth);

    jwt = new JWT().addJWK(new JWK("RS256", null,
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCa4gL1C/Ch7/e1\n" +
        "SkeRxSm9abNCqdm3PccEpvHNz+MFPFQd58kOzzxePDmc1eGXi1eQfMVEBke0OfBf\n" +
        "Tvj/ahw9FJZoGMdhcHvvVp/3VQ+tz19viWHdbVryGZBTqyAqVBXAOdS548OQKbAo\n" +
        "Ky7JfQzDG7A7ARSjivXk0GH8fsW+4dU+epYrX+SWJi1C6QXey9CSllPr+m5DRsQ5\n" +
        "59E4sH4QA8zQ4BoPKSePEJkl6eT0UjILqyQ4pVrFbsJwTniUhSNLUYoVBzjj/5P6\n" +
        "7RUpKaGtF0E1wCFeZ2nCMugNPL8jzP66qQqK10RVzMJ2V42p5vpvWSM9ZLdVstfF\n" +
        "j8shiXO5AgMBAAECggEAIriwOQcoNuV4/qdcTA2LQe9ERJmXOUEcMKrMYntMRYw0\n" +
        "v0+K/0ruGaIeuE4qeLLAOp/+CTXvNTQX8wXdREUhd3/6B/QmHm39GrasveHP1gM7\n" +
        "PeHqkp1FWijo9hjS6SpYhfNxAQtSeCsgVqD3qCvkhIjchR3E5rTsUxN0JAq3ggb9\n" +
        "WCJ2LUxOOTHAWL4cv7FIKfwU/bwjBdHbSLuh7em4IE8tzcFgh49281APprGb4a3d\n" +
        "CPlIZC+CQmTFKPGzT0WDNc3EbPPKcx8ECRf1Zo94Tqnzv7FLgCmr0o4O9e6E3yss\n" +
        "Uwp7EKPUQyAwBkc+pHwqUmOPqHB+z28JUOwqoD0vQQKBgQDNiXSydWh9BUWAleQU\n" +
        "fgSF0bjlt38HVcyMKGC1xQhi8VeAfLJxGCGbdxsPFNCtMPDLRRyd4xHBmsCmPPli\n" +
        "CFHD1UbfNuKma6azl6A86geuTolgrHoxp57tZwoBpG9JHoTA53pfBPxb8q39YXKh\n" +
        "DSXsJVldxsHwzFAklj3ZqzWq3QKBgQDA6M/VW3SXEt1NWwMI+WGa/QKHDjLDhZzF\n" +
        "F3iQTtzDDmA4louAzX1cykNo6Y7SpORi0ralml65iwT2HZtE8w9vbw4LNmBiHmlX\n" +
        "AvpZSHT6/7nQeiFtxZu9cyw4GGpNSaeqp4Cq6TGYmfbq4nIdryzUU2AgsqSZyrra\n" +
        "xh7K+2I4jQKBgGjC8xQy+7sdgLt1qvc29B8xMkkEKl8WwFeADSsY7plf4fW/mURD\n" +
        "xH11S/l35pUgKNuysk9Xealws1kIIyRwkRx8DM+hLg0dOa64Thg+QQP7S9JWl0HP\n" +
        "6hWfO15y7bYbNBcO5TShWe+T1lMb5E1qYjXnI5HEyP1vZjn/yi60MXqRAoGAe6F4\n" +
        "+QLIwL1dSOMoGctBS4QU55so23e41fNJ2CpCf1uqPPn2Y9DOI/aYpxbv6n20xMTI\n" +
        "O2+of37h6h1lUhX38XGZ7YOm15sn5ZTJ/whZuDbFzh9HZ0N6oTq7vyOelPO8WblJ\n" +
        "077pgyRBQ51mhzGqKFVayPnUVZ/Ais7oEyxycU0CgYEAzEUhmN22ykywh0My83z/\n" +
        "7yl2tyrlv2hcZbaP7+9eHdUafGG8jMTVD7jxhzAbiSo2UeyHUnAItDnLetLh89K6\n" +
        "0oF3/rZLqugtb+f48dgRE/SDF4Itgp5fDqWHLhEW7ZhWCFlFgZ3sq0XryIxzFof0\n" +
        "O/Fd1NnotirzTnob5ReblIM="));

    should.assertNotNull(jwt);
  }

  @Test
  public void itShouldAssertThatTokenHasRoles(TestContext should) {

    final Async test = should.async();

    String accessToken = jwt.sign(
      new JsonObject(
        "{\n" +
          "      \"iss\": \"https://server.example.com\",\n" +
          "      \"aud\": \"s6BhdRkqt3\",\n" +
          "      \"jti\": \"a-123\",\n" +
          "      \"exp\": 999999999999,\n" +
          "      \"iat\": 1311280970,\n" +
          "      \"sub\": \"24400320\",\n" +
          "      \"upn\": \"jdoe@server.example.com\",\n" +
          "      \"groups\": [\"red-group\", \"green-group\", \"admin-group\", \"admin\"]\n" +
          "}"), new JWTOptions().setAlgorithm("RS256"));


    AccessToken token = new OAuth2TokenImpl(
      oauth,
      new JsonObject().put("access_token", accessToken).put("type_type", "Bearer"));

    // we ensure that the sign/decode is working as espected
    should.assertNotNull(token.accessToken());

    // assert that the user has the following roles:
    final List<String> roles = Arrays.asList("red-group", "green-group", "admin-group", "admin");

    final AtomicInteger cnt = new AtomicInteger(roles.size());

    for (String role : roles) {
      token.isAuthorized(role, authz -> {
        should.assertTrue(authz.succeeded());
        should.assertTrue(authz.result());
        if (cnt.decrementAndGet() == 0) {
          test.complete();
        }
      });
    }
  }

  @Test
  public void itShouldNotFailForMissingGroupsField(TestContext should) {

    final Async test = should.async();

    String accessToken = jwt.sign(
      new JsonObject(
        "{\n" +
          "      \"iss\": \"https://server.example.com\",\n" +
          "      \"aud\": \"s6BhdRkqt3\",\n" +
          "      \"jti\": \"a-123\",\n" +
          "      \"exp\": 999999999999,\n" +
          "      \"iat\": 1311280970,\n" +
          "      \"sub\": \"24400320\"\n" +
          "}"), new JWTOptions().setAlgorithm("RS256"));


    AccessToken token = new OAuth2TokenImpl(
      oauth,
      new JsonObject().put("access_token", accessToken).put("type_type", "Bearer"));

    // we ensure that the sign/decode is working as espected
    should.assertNotNull(token.accessToken());

    token.isAuthorized("admin", authz -> {
      should.assertTrue(authz.succeeded());
      should.assertFalse(authz.result());
      test.complete();
    });
  }

  @Test
  public void itShouldBeFalseForRoleUnknown(TestContext should) {

    final Async test = should.async();

    String accessToken = jwt.sign(
      new JsonObject(
        "{\n" +
          "      \"iss\": \"https://server.example.com\",\n" +
          "      \"aud\": \"s6BhdRkqt3\",\n" +
          "      \"jti\": \"a-123\",\n" +
          "      \"exp\": 999999999999,\n" +
          "      \"iat\": 1311280970,\n" +
          "      \"sub\": \"24400320\",\n" +
          "      \"upn\": \"jdoe@server.example.com\",\n" +
          "      \"groups\": [\"red-group\", \"green-group\", \"admin-group\", \"admin\"]\n" +
          "}"), new JWTOptions().setAlgorithm("RS256"));


    AccessToken token = new OAuth2TokenImpl(
      oauth,
      new JsonObject().put("access_token", accessToken).put("type_type", "Bearer"));

    // we ensure that the sign/decode is working as espected
    should.assertNotNull(token.accessToken());

    token.isAuthorized("unknown", authz -> {
      should.assertTrue(authz.succeeded());
      should.assertFalse(authz.result());
      test.complete();
    });
  }
}
