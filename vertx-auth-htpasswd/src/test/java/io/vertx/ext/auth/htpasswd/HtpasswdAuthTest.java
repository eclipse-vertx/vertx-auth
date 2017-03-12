package io.vertx.ext.auth.htpasswd;

import io.vertx.core.json.JsonObject;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

/**
 * Created by nevenr on 12/03/2017.
 */
public class HtpasswdAuthTest extends VertxTestBase {

  private HtpasswdAuth authProviderCrypt;
  private HtpasswdAuth authProviderPlainText;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProviderCrypt = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().enableCryptAndDisablePlainTextPwd());
    authProviderPlainText = HtpasswdAuth.create(vertx, new HtpasswdAuthOptions().enablePlainTextAndDisableCryptPwd());
  }

  @Test
  public void bcrypt() {
    JsonObject authInfo = new JsonObject()
      .put("username", "bcrypt")
      .put("password", "myPassword");

    authProviderCrypt.authenticate(authInfo, onFailure(v -> {
      //assertTrue(v instanceof AuthenticationException);
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


}
