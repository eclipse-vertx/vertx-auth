package io.vertx.tests;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn.*;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertNotNull;

@RunWith(VertxUnitRunner.class)
public class NavigatorCredentialsGet {

  private final DummyStore database = new DummyStore();

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Before
  public void resetDatabase() {
    database.clear();
  }

  @Test
  public void testRequestLogin(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    database.add(
      new Authenticator()
        .setUserName("paulo")
        .setCredID("O3ZJlAdXvra6PwvL4I9AP99dS1_v3DDRuB_SwTAHFbUfMtvWTOFycCeb6CkXZXiPWi9Nr0ptUnlnHP3U40ptEA")
        .setPublicKey("pQECAyYgASFYIBl0C67nFN_OwbODu_iE0hI5nM0ppUkqjhU9NhQvBaiLIlggffUTx8E6OM85huU3DcadeuaBBh8kGI8vdm3zesf3YRc")
        .setCounter(2)
    );

    webAuthN.getCredentialsOptions("paulo")
      .onFailure(should::fail)
      .onSuccess(challengeResponse -> {
        assertNotNull(challengeResponse);
        // important fields to be present
        assertNotNull(challengeResponse.getString("challenge"));
        assertNotNull(challengeResponse.getJsonArray("allowCredentials"));
        // ensure that challenge is base64url encoded
        assertNotNull(challengeResponse.getBinary("challenge"));
        test.complete();
      });
  }

  @Test
  public void testLoginRequestChallenge(TestContext should) {
    final Async test = should.async();

    WebAuthn webAuthN = WebAuthn.create(
        rule.vertx(),
        new WebAuthnOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .authenticatorFetcher(database::fetch)
      .authenticatorUpdater(database::store);

    database.add(
      new Authenticator()
        .setUserName("paulo")
        .setCredID("rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9oFrDxZZDmrp3odfuTPuONQCiSMH-Tyg")
        .setPublicKey("pQECAyYgASFYILBNcdWmiMsmjA1QkNpG91GpEbhMIOqWLieDP6mLnGETIlggGMiqXz8BuSiPa0ovGVxxxbdUbJVm6THKNhUCifFhJCE")
        .setCounter(4)
    );

    // Dummy request

    JsonObject body = new JsonObject()
      .put("id", "rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9oFrDxZZDmrp3odfuTPuONQCiSMH-Tyg")
      .put("rawId", "rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9oFrDxZZDmrp3odfuTPuONQCiSMH-Tyg")
      .put("type", "public-key")
      .put("response", new JsonObject()
        .put("authenticatorData", "fxV8VVBPmz66RLzscHpg5yjRhO28Y_fPwYO5AVwzBEIBAAAACA")
        .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiek5hSVduQ213VkY3QTVhWkRGMDRfanRoUG1aVGR6aUk3c1hEa1lFSnhMREgxZDFFeWNjNmtFX1JmMUxaaVNEMEZHQ3JqenJZcTlObVlyQm1jREZGX2ciLCJvcmlnaW4iOiJodHRwczovLzE5Mi4xNjguMTc4LjIwNi54aXAuaW86ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0")
        .put("signature", "MEUCIFXjL0ONRuLP1hkdlRJ8d0ofuRAS12c6w8WgByr-0yQZAiEAw-C6UZ8U8pi8irAcD6jXXaZMtezbzVwZXLGqY3sbFyA")
        .put("userHandle", ""));

    webAuthN.authenticate(new WebAuthnCredentials()
        .setWebauthn(body)
        .setUsername("paulo")
        .setOrigin("https://192.168.178.206.xip.io:8443")
        .setChallenge("zNaIWnCmwVF7A5aZDF04_jthPmZTdziI7sXDkYEJxLDH1d1Eycc6kE_Rf1LZiSD0FGCrjzrYq9NmYrBmcDFF_g"))
      .onFailure(should::fail)
      .onSuccess(user -> {
        assertNotNull(user);
        test.complete();
      });
  }
}
