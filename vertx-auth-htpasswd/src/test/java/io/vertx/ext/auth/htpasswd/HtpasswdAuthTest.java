package io.vertx.ext.auth.htpasswd;

import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
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
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("bcrypt", "myPassword");

    authProviderCrypt.authenticate(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void md5() {
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("md5", "myPassword");

    authProviderCrypt.authenticate(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void sha1() {
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sha1", "myPassword");

    authProviderCrypt.authenticate(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void crypt() {
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("crypt", "myPassword");

    authProviderCrypt.authenticate(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void plaintext() {
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("plaintext", "myPassword");

    authProviderPlainText.authenticate(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  @Test
  public void authzFalse() {
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("md5", "myPassword");

    authProviderUsersAreAuthorizedForNothing.authenticate(credentials, onSuccess(user -> {
      assertNotNull(user);
      assertFalse(PermissionBasedAuthorization.create("something").match(user));
      testComplete();
    }));
    await();
  }

}
