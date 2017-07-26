package io.vertx.ext.auth.htpasswd;

import io.vertx.core.json.JsonObject;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Neven Radovanović
 */
public class HtpasswdAuthTest extends VertxTestBase {

  private HtpasswdAuth authProviderCrypt;
  private HtpasswdAuth authProviderPlainText;
  private HtpasswdAuth authProviderUsersAreAuthorizedForEverything;
  private HtpasswdAuth authProviderUsersAreAuthorizedForNothing;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProviderCrypt = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().enableCryptAndDisablePlainTextPwd());
    authProviderPlainText = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().enablePlainTextAndDisableCryptPwd());

    authProviderUsersAreAuthorizedForEverything = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().setUsersAuthorizedForEverything(true));
    authProviderUsersAreAuthorizedForNothing = HtpasswdAuth.create(vertx);
  }

  @Test
  @Ignore
  public void bcrypt2y() {
    JsonObject authInfo = new JsonObject()
      .put("username", "bcrypt2y")
      .put("password", "myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void bcrypt2a() {
    JsonObject authInfo = new JsonObject()
      .put("username", "bcrypt2a")
      .put("password", "abcdefghijklmnopqrstuvwxyz");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void md5() {
    JsonObject authInfo = new JsonObject()
      .put("username", "md5")
      .put("password", "myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void sha1() {
    JsonObject authInfo = new JsonObject()
      .put("username", "sha1")
      .put("password", "myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void crypt() {
    JsonObject authInfo = new JsonObject()
      .put("username", "crypt")
      .put("password", "myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void plaintext() {
    JsonObject authInfo = new JsonObject()
      .put("username", "plaintext")
      .put("password", "myPassword");

    authProviderPlainText.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void authzTrue() {
    JsonObject authInfo = new JsonObject()
      .put("username", "md5")
      .put("password", "myPassword");

    authProviderUsersAreAuthorizedForEverything.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("something", onSuccess(res -> {
        assertTrue(res);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void authzFalse() {
    JsonObject authInfo = new JsonObject()
      .put("username", "md5")
      .put("password", "myPassword");

    authProviderUsersAreAuthorizedForNothing.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("something", onSuccess(res -> {
        assertFalse(res);
        testComplete();
      }));
    }));
    await();
  }

}
