package io.vertx.ext.auth.test.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.mongo.MongoAuthProvider;
import io.vertx.ext.auth.mongo.MongoAuthService;
import io.vertx.ext.mongo.MongoService;

import java.util.concurrent.CountDownLatch;

import org.junit.Test;

/**
 * @author mremme
 */

public class MongoAuthTest extends MongoBaseTest {
  protected MongoAuthService authService;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    initMongoService();
    initAuthService();
    initTestUsers();
  }

  @Override
  public void tearDown() throws Exception {
    mongoService.stop();
    super.tearDown();
  }

  /**
   * Test a user with unique username and password
   */
  @Test
  public void testLoginUniqueUser() {
    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Michael").put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps1");
    authService.login(credentials, onSuccess(res -> {
      System.out.println(String.valueOf(res));
      assertNotNull(res);

      testComplete();
    }));
    await();
  }

  //  /**
  //   * Test a user with duplicate username and unique password. This should be accepted by the default implementation
  //   */
  //  @Test
  //  public void testLoginDoublette1() {
  //    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Doublette").put(
  //        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps1");
  //    authService.login(credentials, onSuccess(res -> {
  //      assertNotNull(res);
  //      testComplete();
  //    }));
  //    await();
  //  }
  //
  //  /**
  //   * Test a user with duplicate username AND duplicate password. This should NOT be accepted by the default
  //   * implementation
  //   */
  //  @Test
  //  public void testLoginDoublette2() {
  //    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Doublette").put(
  //        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps2");
  //    authService.login(credentials, onSuccess(res -> {
  //      assertNotNull(res);
  //      testComplete();
  //    }));
  //    await();
  //  }

  // testen von Null Passwort in User, Null-Passwort in Request, Null Username dito

  private void initAuthService() {
    authService = new MongoAuthService(vertx, mongoService, createDefaultConfig());
  }

  private JsonObject createDefaultConfig() {
    JsonObject js = new JsonObject();
    return js;
  }

  private void initMongoService() throws Exception {
    JsonObject config = getConfig();
    mongoService = MongoService.create(vertx, config);
    mongoService.start();
    CountDownLatch latch = new CountDownLatch(1);
    dropCollections(latch);
    awaitLatch(latch);
  }

  private void initTestUsers() {
    assertTrue(initOneUser("Michael", "ps1"));

    assertTrue(initOneUser("Doublette", "ps1"));
    assertTrue(initOneUser("Doublette", "ps2"));
    assertTrue(initOneUser("Doublette", "ps2"));

  }

  private boolean initOneUser(String username, String password) {
    JsonObject user = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, username).put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, password);
    final StringBuffer returnString = new StringBuffer();
    mongoService.save(MongoAuthProvider.DEFAULT_COLLECTION_NAME, user, res -> {

      if (res.succeeded()) {
      } else {
        res.cause().printStackTrace();
        returnString.append("failed");
      }
    });
    return returnString.length() == 0;
  }
}
