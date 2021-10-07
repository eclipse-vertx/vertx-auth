package io.vertx.ext.auth.htpasswd;

import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author Neven Radovanović
 */
@RunWith(VertxUnitRunner.class)
public class HtpasswdAuthTest {

  @Rule
  public RunTestOnContext rule = new RunTestOnContext();

  private HtpasswdAuth authProviderCrypt;
  private HtpasswdAuth authProviderPlainText;
  private HtpasswdAuth authProviderUsersAreAuthorizedForNothing;

  @Before
  public void setUp() {
    authProviderCrypt = HtpasswdAuth.create(rule.vertx());
    authProviderPlainText = HtpasswdAuth.create(rule.vertx(), new HtpasswdAuthOptions().setPlainTextEnabled(true));
    authProviderUsersAreAuthorizedForNothing = HtpasswdAuth.create(rule.vertx());
  }

  @Test
  @Ignore("No bcrypt implementation available")
  public void bcrypt(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("bcrypt", "myPassword");

    authProviderCrypt.authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void md5(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("md5", "myPassword");

    authProviderCrypt.authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void sha1(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sha1", "myPassword");

    authProviderCrypt.authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void crypt(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("crypt", "myPassword");

    authProviderCrypt.authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void plaintext(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("plaintext", "myPassword");

    authProviderPlainText
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        test.complete();
      });
  }

  @Test
  public void authzFalse(TestContext should) {
    final Async test = should.async();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("md5", "myPassword");

    authProviderUsersAreAuthorizedForNothing
      .authenticate(credentials)
      .onFailure(should::fail)
      .onSuccess(user -> {
        should.assertNotNull(user);
        should.assertFalse(PermissionBasedAuthorization.create("something").match(user));
        test.complete();
      });
  }
}
