package io.vertx.ext.auth.htpasswd;

import io.vertx.core.json.JsonObject;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;

/**
 * Created by nevenr on 12/03/2017.
 */
public class HtpasswdAuthTest extends VertxTestBase {

  private HtpasswdAuth authProvider;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    authProvider = HtpasswdAuth.create(vertx);
  }

  @Test
  public void bcrypt() {
    JsonObject authInfo = new JsonObject()
      .put("username", "bcrypt")
      .put("password", "myPassword");

    authProvider.authenticate(authInfo, onFailure(v -> {
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

    authProvider.authenticate(authInfo, onSuccess(res -> {
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

    authProvider.authenticate(authInfo, onSuccess(res -> {
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

    authProvider.authenticate(authInfo, onSuccess(res -> {
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

    authProvider.authenticate(authInfo, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }


}
