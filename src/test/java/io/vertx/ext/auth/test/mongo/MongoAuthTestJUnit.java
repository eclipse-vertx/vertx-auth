package io.vertx.ext.auth.test.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.mongo.MongoAuthProvider;
import io.vertx.ext.auth.mongo.MongoAuthService;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runners.model.InitializationError;

/**
 * @author mremme
 */

public class MongoAuthTestJUnit extends MongoBaseTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthTestJUnit.class);

  protected MongoAuthService  authService;

  @BeforeClass
  public static void beforeClass() throws Exception {
    System.setProperty("connection_string", "mongodb://localhost:27017");
    System.setProperty("db_name", "TestDatabase");

    MongoBaseTest.startMongo();
  }

  @AfterClass
  public static void afterClass() {
    MongoBaseTest.stopMongo();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    getMongoService();
    initAuthService();
  }

  @Override
  public void tearDown() throws Exception {
    super.tearDown();
  }

  /**
   * Test a user with unique username and password
   */
  @Test
  public void testLoginUniqueUser() {
    log.info("testLoginUniqueUser");
    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Michael").put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps1");
    authService.login(credentials, onSuccess(res -> {
      log.info(res);
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  /**
   * Test a user with duplicate username and unique password. This should be accepted by the default implementation
   */
  @Test
  public void testLoginDoublette1() {
    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Doublette").put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps1");
    authService.login(credentials, onSuccess(res -> {
      assertNotNull(res);
      testComplete();
    }));
    await();
  }

  /**
   * Test a user with duplicate username AND duplicate password. This should NOT be accepted
   */
  @Test
  public void testLoginDoublette2() {
    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Doublette").put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps2");
    authService.login(credentials, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();

  }

  // testen von Null Passwort in User, Null-Passwort in Request, Null Username dito

  private void initAuthService() throws Exception {
    if (authService == null) {
      log.info("initAuthService");
      authService = new MongoAuthService(vertx, getMongoService(), createAuthServiceConfig());
    }
  }

  private JsonObject createAuthServiceConfig() {
    JsonObject js = new JsonObject();
    js.put(MongoAuthProvider.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuthProvider.DEFAULT_COLLECTION_NAME));
    return js;
  }

  @Override
  public void initDemoData() throws Exception {
    initTestUsers();
  }

  private void initTestUsers() throws Exception {
    log.info("initTestUsers");
    List<JsonObject> users = createUserList();
    CountDownLatch latch = new CountDownLatch(users.size());

    for (JsonObject user : users) {
      if (!initOneUser(user, latch))
        throw new InitializationError("could not create users");
    }
    awaitLatch(latch);
    if (!verifyUserData())
      throw new InitializationError("users weren't created");

  }

  private boolean verifyUserData() throws Exception {
    log.info("verifyUserData");
    final StringBuffer buffer = new StringBuffer();
    CountDownLatch intLatch = new CountDownLatch(1);
    getMongoService().count(createCollectionName(MongoAuthProvider.DEFAULT_COLLECTION_NAME), new JsonObject(), res -> {
      if (res.succeeded()) {
        log.info(res.result() + " users found");
      } else {
        log.error("", res.cause());
        buffer.append("false");
      }
      intLatch.countDown();
    });
    awaitLatch(intLatch);
    return buffer.length() == 0;
  }

  protected List<JsonObject> createUserList() {
    List<JsonObject> users = new ArrayList<JsonObject>();
    users.add(createUser("Michael", "ps1"));
    users.add(createUser("Doublette", "ps1"));
    users.add(createUser("Doublette", "ps2"));
    users.add(createUser("Doublette", "ps2"));
    return users;
  }

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  protected JsonObject createUser(String username, String password) {
    JsonObject user = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, username).put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, password);
    return user;
  }

  /**
   * Creates a user inside mongo. Returns true, if user was successfully added
   * 
   * @param user
   * @param latch
   * @return
   * @throws Exception
   * @throws Throwable
   */
  private boolean initOneUser(JsonObject user, CountDownLatch latch) throws Exception {
    CountDownLatch intLatch = new CountDownLatch(1);
    final StringBuffer buffer = new StringBuffer();
    getMongoService().save(createCollectionName(MongoAuthProvider.DEFAULT_COLLECTION_NAME), user, res -> {
      if (res.succeeded()) {
        log.info("user added: " + user.getString(MongoAuthProvider.DEFAULT_USERNAME_FIELD));
        latch.countDown();
      } else {
        log.error("", res.cause());
        buffer.append("false");
      }
      intLatch.countDown();
    });
    awaitLatch(intLatch);
    return buffer.length() == 0;
  }

}
