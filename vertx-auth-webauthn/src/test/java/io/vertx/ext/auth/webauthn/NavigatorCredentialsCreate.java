package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.Codec;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.naming.AuthenticationException;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class NavigatorCredentialsCreate {

  private final DummyStore database = new DummyStore();

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Before
  public void resetDatabase() {
    database.clear();
  }

  @Test
  public void testRequestRegister(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
      rule.vertx(),
      new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation"))
    .setAttestation(Attestation.of("direct")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final String userId = Codec.base64UrlEncode(UUID.randomUUID().toString().getBytes());

    // Authenticator to test excludedCredentials
    database.add(
      new Authenticator()
        .setUserId(userId)
        .setType("public-key")
        .setCredID("-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw")
    );

    // Dummy user
    JsonObject user = new JsonObject()
      .put("id", userId)
      .put("name", "john.doe@email.com")
      .put("displayName", "John Doe")
      .put("icon", "https://pics.example.com/00/p/aBjjjpqPb.png");

    webAuthN
      .createCredentialsOptions(user)
      .onFailure(should::fail)
      .onSuccess(challengeResponse -> {
        assertNotNull(challengeResponse);
        // important fields to be present
        assertNotNull(challengeResponse.getString("challenge"));
        assertNotNull(challengeResponse.getJsonObject("rp"));
        assertNotNull(challengeResponse.getJsonObject("user"));
        assertNotNull(challengeResponse.getJsonArray("pubKeyCredParams"));
        // ensure that challenge and user.id are base64url encoded
        assertNotNull(challengeResponse.getBinary("challenge"));

        final JsonObject challengeResponseUser = challengeResponse.getJsonObject("user");
        assertNotNull(challengeResponseUser);
        assertEquals(userId, challengeResponseUser.getString("id"));
        assertEquals(user.getString("name"), challengeResponseUser.getString("name"));
        assertEquals(user.getString("displayName"), challengeResponseUser.getString("displayName"));
        assertEquals(user.getString("icon"), challengeResponseUser.getString("icon"));

        final JsonArray excludeCredentials = challengeResponse.getJsonArray("excludeCredentials");
        assertEquals(1, excludeCredentials.size());

        final JsonObject excludeCredential = excludeCredentials.getJsonObject(0);
        assertEquals("public-key", excludeCredential.getString("type"));
        assertEquals("-r1iW_eHUyIpU93f77odIrdUlNVfYzN-JPCTWGtdn-1wxdLxhlS9NmzLNbYsQ7XVZlGSWbh_63E5oFHcNh4JNw", excludeCredential.getString("id"));
        assertEquals(new JsonArray(Arrays.asList("usb", "nfc", "ble", "internal")), excludeCredential.getJsonArray("transports"));

        test.complete();
      });
  }

  @Test
  public void testRequestRegisterWithRawId(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation"))
          .setAttestation(Attestation.of("direct")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    final String userId = Codec.base64UrlEncode(UUID.randomUUID().toString().getBytes());

    // Dummy user
    JsonObject user = new JsonObject()
      .put("rawId", userId)
      .put("displayName", "John Doe");

    webAuthN
      .createCredentialsOptions(user)
      .onFailure(should::fail)
      .onSuccess(challengeResponse -> {
        final JsonObject challengeResponseUser = challengeResponse.getJsonObject("user");
        assertNotNull(challengeResponseUser);
        assertEquals("rawId should have been used as-is", user.getString("rawId"), challengeResponseUser.getString("id"));
        test.complete();
      });
  }

  @Test
  public void testRequestRegisterWithNoId(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation"))
          .setAttestation(Attestation.of("direct")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    // Dummy user
    JsonObject user = new JsonObject()
      .put("displayName", "John Doe");

    webAuthN
      .createCredentialsOptions(user)
      .onFailure(should::fail)
      .onSuccess(challengeResponse -> {
        final JsonObject challengeResponseUser = challengeResponse.getJsonObject("user");
        assertNotNull(challengeResponseUser);
        assertNotNull("random id should have been generated", challengeResponseUser.getBinary("id"));
        test.complete();
      });
  }

  @Test
  public void testRegister(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
      rule.vertx(),
      new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    // dummy request
    JsonObject request = new JsonObject()
      .put("id", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyLncRav5Ivd7T1dav3eWrI7CT8HmzU_yAYJrmja4in8OFL3A")
      .put("rawId", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyLncRav5Ivd7T1dav3eWrI7CT8HmzU_yAYJrmja4in8OFL3A")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("attestationObject", "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEfxV8VVBPmz66RLzscHpg5yjRhO28Y_fPwYO5AVwzBEJBAAAAAwAAAAAAAAAAAAAAAAAAAAAAQEPjBz9F6ttAijOS1t6gbfYLub3TmCzWXN4wnIMsi53EWr-SL3e09XWr93lqyOwk_B5s1P8gGCa5o2uIp_DhS9ylAQIDJiABIVggN_D3u-03a0GzONOHfaML881QZtOCc5oTNRB2wlyqUEUiWCD3878XoO_bIJf0mEPDILODFhVmkc4QeR6hOIDvwvXzYQ")
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQkg3RUtJRFhVNkN0Xzk2eFR6RzBsNjJxTWhXX0VmX0s0TVFkRExvVk5jMVVYTVFZNHFOOWFnNXlETm1MSTd2RlJzbGtRYmJqMEpaV0p4R1ZmTXVnWGciLCJvcmlnaW4iOiJodHRwczovLzE5Mi4xNjguMTc4LjIwNi54aXAuaW86ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"));

    webAuthN
      .authenticate(
        new JsonObject()
          .put("username", "paulo")
          .put("origin", "https://192.168.178.206.xip.io:8443")
          .put("domain", "192.168.178.206.xip.io")
          .put("challenge", "BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UXMQY4qN9ag5yDNmLI7vFRslkQbbj0JZWJxGVfMugXg")
          .put("webauthn", request))
      .onFailure(should::fail)
      .onSuccess(response -> {
        assertNotNull(response);
        test.complete();
      });
  }
}
