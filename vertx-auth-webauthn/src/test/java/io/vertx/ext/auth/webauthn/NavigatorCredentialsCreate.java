package io.vertx.ext.auth.webauthn;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertNotNull;

@RunWith(VertxUnitRunner.class)
public class NavigatorCredentialsCreate {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void testRequestRegister(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
      rule.vertx(),
      new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .setAuthenticatorStore(new DummyStore());

    // Dummy user
    JsonObject user = new JsonObject()
      // id is expected to be a base64url string
      .put("id", "000000000000000000000000")
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
        assertNotNull(challengeResponse.getJsonObject("user").getBinary("id"));
        test.complete();
      });
  }

  @Test
  public void testRegister(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
      rule.vertx(),
      new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .setAuthenticatorStore(new DummyStore());

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
