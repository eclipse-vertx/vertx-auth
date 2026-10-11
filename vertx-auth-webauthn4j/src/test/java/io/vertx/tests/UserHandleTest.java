package io.vertx.tests;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import io.vertx.ext.auth.webauthn4j.RelyingParty;
import io.vertx.ext.auth.webauthn4j.WebAuthn4J;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JCredentials;
import io.vertx.ext.auth.webauthn4j.WebAuthn4JOptions;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Base64;

/**
 * Tests for the user handle ({@code user.id}) handling: it must be taken from the caller when provided at
 * registration (issue #580) and it must be stored, returned in the principal and verified against the
 * assertion {@code userHandle} at authentication (issue #581).
 */
@RunWith(VertxUnitRunner.class)
public class UserHandleTest {

  // 16 bytes, base64url without padding
  private static final String USER_ID = "AAECAwQFBgcICQoLDA0ODw";
  private static final String OTHER_USER_ID = "Dw4NDAsKCQgHBgUEAwIBAA";

  private static final String CRED_ID = "rYLaf9xagyA2YnO-W3CZDW8udSg8VeMMm25nenU7nCSxUqy1pEzOdb9oFrDxZZDmrp3odfuTPuONQCiSMH-Tyg";
  private static final String PUBLIC_KEY = "pQECAyYgASFYILBNcdWmiMsmjA1QkNpG91GpEbhMIOqWLieDP6mLnGETIlggGMiqXz8BuSiPa0ovGVxxxbdUbJVm6THKNhUCifFhJCE";
  private static final String ORIGIN = "https://192.168.178.206.xip.io:8443";
  private static final String GET_CHALLENGE = "zNaIWnCmwVF7A5aZDF04_jthPmZTdziI7sXDkYEJxLDH1d1Eycc6kE_Rf1LZiSD0FGCrjzrYq9NmYrBmcDFF_g";

  private final DummyStore database = new DummyStore();

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  private WebAuthn4J webAuthN;

  @Before
  public void setUp() {
    database.clear();
    webAuthN = WebAuthn4J.create(
        rule.vertx(),
        new WebAuthn4JOptions().setRelyingParty(new RelyingParty().setName("ACME Corporation")))
      .credentialStorage(database);
  }

  // ---- issue #580: createCredentialsOptions must honour user.id ----

  @Test
  public void testCreateOptionsUsesGivenUserId(TestContext should) {
    final Async test = should.async();

    JsonObject user = new JsonObject()
      .put("id", USER_ID)
      .put("name", "john.doe@email.com")
      .put("displayName", "John Doe");

    webAuthN
      .createCredentialsOptions(user)
      .onFailure(should::fail)
      .onSuccess(options -> {
        should.assertEquals(USER_ID, options.getJsonObject("user").getString("id"));
        test.complete();
      });
  }

  @Test
  public void testCreateOptionsGeneratesUserIdWhenMissing(TestContext should) {
    final Async test = should.async();

    webAuthN
      .createCredentialsOptions(new JsonObject().put("name", "john.doe@email.com"))
      .onFailure(should::fail)
      .onSuccess(options -> {
        String id = options.getJsonObject("user").getString("id");
        should.assertNotNull(id);
        // valid base64url, 16 bytes (a UUID)
        should.assertEquals(16, Base64.getUrlDecoder().decode(id).length);
        // and different for every call
        webAuthN
          .createCredentialsOptions(new JsonObject().put("name", "john.doe@email.com"))
          .onFailure(should::fail)
          .onSuccess(options2 -> {
            should.assertNotEquals(id, options2.getJsonObject("user").getString("id"));
            test.complete();
          });
      });
  }

  @Test
  public void testCreateOptionsRejectsNonBase64UrlUserId(TestContext should) {
    final Async test = should.async();

    webAuthN
      .createCredentialsOptions(new JsonObject().put("id", "not base64url!").put("name", "john.doe@email.com"))
      .onSuccess(options -> should.fail("user.id that is not base64url must be rejected"))
      .onFailure(err -> test.complete());
  }

  @Test
  public void testCreateOptionsRejectsTooLongUserId(TestContext should) {
    final Async test = should.async();

    // 65 bytes, the spec limits the user handle to 64 bytes
    String tooLong = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[65]);

    webAuthN
      .createCredentialsOptions(new JsonObject().put("id", tooLong).put("name", "john.doe@email.com"))
      .onSuccess(options -> should.fail("user.id longer than 64 bytes must be rejected"))
      .onFailure(err -> test.complete());
  }

  @Test
  public void testCreateOptionsRejectsEmptyUserId(TestContext should) {
    final Async test = should.async();

    webAuthN
      .createCredentialsOptions(new JsonObject().put("id", "").put("name", "john.doe@email.com"))
      .onSuccess(options -> should.fail("empty user.id must be rejected"))
      .onFailure(err -> test.complete());
  }

  // ---- issue #581: registration stores the user id and exposes it in the principal ----

  @Test
  public void testRegisterStoresUserId(TestContext should) {
    final Async test = should.async();

    webAuthN
      .authenticate(registrationCredentials().setUserId(USER_ID))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertEquals(USER_ID, user.principal().getString("userId"));
        database.find("paulo", null)
          .onFailure(should::fail)
          .onSuccess(authenticators -> {
            should.assertEquals(1, authenticators.size());
            should.assertEquals(USER_ID, authenticators.get(0).getUserId());
            test.complete();
          });
      });
  }

  @Test
  public void testRegisterWithoutUserIdIsStillAllowed(TestContext should) {
    final Async test = should.async();

    webAuthN
      .authenticate(registrationCredentials())
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNull(user.principal().getString("userId"));
        test.complete();
      });
  }

  // ---- issue #581: authentication verifies the assertion userHandle against the stored user id ----

  @Test
  public void testLoginMatchingUserHandle(TestContext should) {
    final Async test = should.async();

    database.add(storedAuthenticator().setUserId(USER_ID));

    webAuthN
      .authenticate(loginCredentials(USER_ID))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertEquals(USER_ID, user.principal().getString("userId"));
        test.complete();
      });
  }

  @Test
  public void testLoginMismatchingUserHandleIsRejected(TestContext should) {
    final Async test = should.async();

    database.add(storedAuthenticator().setUserId(USER_ID));

    webAuthN
      .authenticate(loginCredentials(OTHER_USER_ID))
      .onSuccess(user -> should.fail("assertion userHandle does not match the credential owner"))
      .onFailure(err -> test.complete());
  }

  @Test
  public void testLoginMismatchingExpectedUserIdIsRejected(TestContext should) {
    final Async test = should.async();

    database.add(storedAuthenticator().setUserId(USER_ID));

    // the relying party identified the user before the ceremony, but the credential belongs to someone else
    webAuthN
      .authenticate(loginCredentials(USER_ID).setUserId(OTHER_USER_ID))
      .onSuccess(user -> should.fail("credential does not belong to the expected user"))
      .onFailure(err -> test.complete());
  }

  @Test
  public void testLoginMatchingExpectedUserId(TestContext should) {
    final Async test = should.async();

    database.add(storedAuthenticator().setUserId(USER_ID));

    webAuthN
      .authenticate(loginCredentials(USER_ID).setUserId(USER_ID))
      .onFailure(should::fail)
      .onSuccess(user -> test.complete());
  }

  @Test
  public void testLoginLegacyAuthenticatorWithoutUserId(TestContext should) {
    final Async test = should.async();

    // authenticators registered before the user id was stored must keep working, whatever the userHandle
    database.add(storedAuthenticator());

    webAuthN
      .authenticate(loginCredentials(OTHER_USER_ID))
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNull(user.principal().getString("userId"));
        test.complete();
      });
  }

  @Test
  public void testLoginEmptyUserHandleIsIgnored(TestContext should) {
    final Async test = should.async();

    // some authenticators return an empty user handle for non discoverable credentials
    database.add(storedAuthenticator().setUserId(USER_ID));

    webAuthN
      .authenticate(loginCredentials(""))
      .onFailure(should::fail)
      .onSuccess(user -> test.complete());
  }

  // ---- fixtures ----

  private static Authenticator storedAuthenticator() {
    return new Authenticator()
      .setUsername("paulo")
      .setCredID(CRED_ID)
      .setPublicKey(PUBLIC_KEY)
      .setCounter(4);
  }

  private static WebAuthn4JCredentials loginCredentials(String userHandle) {
    JsonObject response = new JsonObject()
      .put("authenticatorData", "fxV8VVBPmz66RLzscHpg5yjRhO28Y_fPwYO5AVwzBEIBAAAACA")
      .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiek5hSVduQ213VkY3QTVhWkRGMDRfanRoUG1aVGR6aUk3c1hEa1lFSnhMREgxZDFFeWNjNmtFX1JmMUxaaVNEMEZHQ3JqenJZcTlObVlyQm1jREZGX2ciLCJvcmlnaW4iOiJodHRwczovLzE5Mi4xNjguMTc4LjIwNi54aXAuaW86ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0")
      .put("signature", "MEUCIFXjL0ONRuLP1hkdlRJ8d0ofuRAS12c6w8WgByr-0yQZAiEAw-C6UZ8U8pi8irAcD6jXXaZMtezbzVwZXLGqY3sbFyA");
    if (userHandle != null) {
      response.put("userHandle", userHandle);
    }
    return new WebAuthn4JCredentials()
      .setWebauthn(new JsonObject()
        .put("id", CRED_ID)
        .put("rawId", CRED_ID)
        .put("type", "public-key")
        .put("response", response))
      .setUsername("paulo")
      .setOrigin(ORIGIN)
      .setChallenge(GET_CHALLENGE);
  }

  private static WebAuthn4JCredentials registrationCredentials() {
    return new WebAuthn4JCredentials()
      .setUsername("paulo")
      .setOrigin(ORIGIN)
      .setDomain("192.168.178.206.xip.io")
      .setChallenge("BH7EKIDXU6Ct_96xTzG0l62qMhW_Ef_K4MQdDLoVNc1UXMQY4qN9ag5yDNmLI7vFRslkQbbj0JZWJxGVfMugXg")
      .setWebauthn(new JsonObject()
        .put("id", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyLncRav5Ivd7T1dav3eWrI7CT8HmzU_yAYJrmja4in8OFL3A")
        .put("rawId", "Q-MHP0Xq20CKM5LW3qBt9gu5vdOYLNZc3jCcgyyLncRav5Ivd7T1dav3eWrI7CT8HmzU_yAYJrmja4in8OFL3A")
        .put("type", "public-key")
        .put("response", new JsonObject()
          .put("attestationObject", "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEfxV8VVBPmz66RLzscHpg5yjRhO28Y_fPwYO5AVwzBEJBAAAAAwAAAAAAAAAAAAAAAAAAAAAAQEPjBz9F6ttAijOS1t6gbfYLub3TmCzWXN4wnIMsi53EWr-SL3e09XWr93lqyOwk_B5s1P8gGCa5o2uIp_DhS9ylAQIDJiABIVggN_D3u-03a0GzONOHfaML881QZtOCc5oTNRB2wlyqUEUiWCD3878XoO_bIJf0mEPDILODFhVmkc4QeR6hOIDvwvXzYQ")
          .put("clientDataJSON", "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQkg3RUtJRFhVNkN0Xzk2eFR6RzBsNjJxTWhXX0VmX0s0TVFkRExvVk5jMVVYTVFZNHFOOWFnNXlETm1MSTd2RlJzbGtRYmJqMEpaV0p4R1ZmTXVnWGciLCJvcmlnaW4iOiJodHRwczovLzE5Mi4xNjguMTc4LjIwNi54aXAuaW86ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0")));
  }
}
