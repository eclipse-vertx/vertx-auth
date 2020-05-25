package io.vertx.ext.auth.htpasswd;

import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.test.core.VertxTestBase;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Neven Radovanović
 */
public class HtpasswdAuthTest extends VertxTestBase {

  private HtpasswdAuth authProviderCrypt;
  private HtpasswdAuth authProviderPlainText;
  private HtpasswdAuth authProviderUsersAreAuthorizedForNothing;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProviderCrypt = HtpasswdAuth.create(vertx);
    authProviderPlainText = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().setPlainTextEnabled(true));
    authProviderUsersAreAuthorizedForNothing = HtpasswdAuth.create(vertx);
  }

  @Test
  @Ignore
  public void bcrypt() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("bcrypt")
      .setPassword("myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void md5() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("md5")
      .setPassword("myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void sha1() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("sha1")
      .setPassword("myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void crypt() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("crypt")
      .setPassword("myPassword");

    authProviderCrypt.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void plaintext() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("plaintext")
      .setPassword("myPassword");

    authProviderPlainText.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void authzFalse() {
    HtpasswdAuthInfo authInfo = new HtpasswdAuthInfo()
      .setUsername("md5")
      .setPassword("myPassword");

    authProviderUsersAreAuthorizedForNothing.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      assertFalse(PermissionBasedAuthorization.create("something").match(user));
      testComplete();
    }));
    await();
  }

}
