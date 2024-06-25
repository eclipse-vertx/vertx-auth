package io.vertx.ext.auth.test.jwt;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.jwt.authorization.MicroProfileAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;

@RunWith(VertxUnitRunner.class)
public class MicroProfileTest {
  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void itShouldAssertThatTokenHasRoles(TestContext should) {

    final Async test = should.async();

    User user = User.create(
      new JsonObject().put("access_token", "jwt"),
      new JsonObject()
        .put("accessToken",
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
              "}")));


    // assert that the user has the following roles:
    final List<String> roles = Arrays.asList("red-group", "green-group", "admin-group", "admin");

    MicroProfileAuthorization.create().getAuthorizations(user)
      .onComplete(call -> {
        should.assertTrue(call.succeeded());
        for (String role : roles) {
          should.assertTrue(RoleBasedAuthorization.create(role).match(user));
        }
        test.complete();
      });
  }

  @Test
  public void itShouldNotFailForMissingGroupsField(TestContext should) {

    final Async test = should.async();

    User user = User.create(
      new JsonObject().put("access_token", "jwt"),
      new JsonObject().put("accessToken",
        new JsonObject(
          "{\n" +
            "      \"iss\": \"https://server.example.com\",\n" +
            "      \"aud\": \"s6BhdRkqt3\",\n" +
            "      \"jti\": \"a-123\",\n" +
            "      \"exp\": 999999999999,\n" +
            "      \"iat\": 1311280970,\n" +
            "      \"sub\": \"24400320\"\n" +
            "}")));

    MicroProfileAuthorization.create().getAuthorizations(user)
      .onComplete(call -> {
        should.assertTrue(call.succeeded());
        test.complete();
      });
  }

  @Test
  public void itShouldBeFalseForRoleUnknown(TestContext should) {

    final Async test = should.async();

    User user = User.create(
      new JsonObject().put("access_token", "jwt"),
      new JsonObject().put("accessToken",
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
            "}")));

    MicroProfileAuthorization.create().getAuthorizations(user)
      .onComplete(call -> {
        should.assertTrue(call.succeeded());
        should.assertFalse(user.authorizations().isEmpty());
        should.assertFalse(RoleBasedAuthorization.create("unknown").match(user));
        test.complete();
      });
  }
}
