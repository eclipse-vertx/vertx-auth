package io.vertx.ext.auth.mongo.test;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.mongo.AuthenticationException;
import io.vertx.ext.auth.mongo.MongoAuth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runners.model.InitializationError;

/**
 * Testing MongoAuth with no encryption for the user password
 * 
 * @author mremme
 */

public class MongoAuthTestNO_SALT extends MongoBaseTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthTestNO_SALT.class);

  protected MongoAuth         authProvider;

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
    initDemoData();
  }

  @Override
  protected void tearDown() throws Exception {
    super.tearDown();
  }

  @Test
  public void testAuthenticate() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadPwd() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "eggs");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertTrue(v instanceof AuthenticationException);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthenticateFailBadUser() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "blah").put(authProvider.getPasswordField(), "whatever");
    authProvider.authenticate(authInfo, onFailure(v -> {
      assertTrue(v instanceof AuthenticationException);
      testComplete();
    }));
    await();
  }

  @Test
  public void testAuthoriseHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("role:developer", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasRole() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("role:manager", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("commit_code", onSuccess(has -> {
        assertTrue(has);
        testComplete();
      }));
    }));
    await();
  }

  @Test
  public void testAuthoriseNotHasPermission() {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), "tim").put(authProvider.getPasswordField(), "sausages");
    authProvider.authenticate(authInfo, onSuccess(user -> {
      assertNotNull(user);
      user.isAuthorised("eat_sandwich", onSuccess(has -> {
        assertFalse(has);
        testComplete();
      }));
    }));
    await();
  }

  /* ##################################################
   * preparation methods
   * ##################################################
   */
  protected List<User> createUserList() {
    List<User> users = new ArrayList<User>();
    users.add(createUser("Michael", "ps1"));
    users.add(createUser("Doublette", "ps1"));
    users.add(createUser("Doublette", "ps2"));
    users.add(createUser("Doublette", "ps2"));

    users.add(createUser("tim", "sausages", Arrays.asList("morris_dancer", "superadmin", "developer"),
        Arrays.asList("commit_code", "merge_pr", "do_actual_work", "bang_sticks")));
    return users;
  }

  protected void initAuthService() throws Exception {
    if (authProvider == null) {
      log.info("initAuthService");
      authProvider = MongoAuth.create(vertx, getMongoService(), createAuthServiceConfig());
    }
  }

  protected JsonObject createAuthServiceConfig() {
    JsonObject js = new JsonObject();
    js.put(MongoAuth.PROPERTY_COLLECTION_NAME, createCollectionName(MongoAuth.DEFAULT_COLLECTION_NAME));
    return js;
  }

  @Override
  public void initDemoData() throws Exception {
    initTestUsers();
  }

  private void initTestUsers() throws Exception {
    log.info("initTestUsers");
    List<User> users = createUserList();
    CountDownLatch latch = new CountDownLatch(users.size());

    for (User user : users) {
      if (!initOneUser(user, latch))
        throw new InitializationError("could not create users");
    }
    awaitLatch(latch);
    if (!verifyUserData())
      throw new InitializationError("users weren't created");

  }

  private boolean verifyUserData() throws Exception {
    final StringBuffer buffer = new StringBuffer();
    CountDownLatch intLatch = new CountDownLatch(1);
    String collectionName = authProvider.getCollectionName();
    log.info("verifyUserData in " + collectionName);
    getMongoService().find(collectionName, new JsonObject(), res -> {
      if (res.succeeded()) {
        log.info(res.result().size() + " users found: " + res.result());

      } else {
        log.error("", res.cause());
        buffer.append("false");
      }
      intLatch.countDown();
    });
    awaitLatch(intLatch);
    return buffer.length() == 0;
  }

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  protected User createUser(String username, String password) {
    return createUser(username, password, null, null);
  }

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  protected User createUser(String username, String password, List<String> roles, List<String> permissions) {
    User user = authProvider.getUserFactory().createUser(username, password, roles, permissions, authProvider);
    String userpassword = user.principal().getString(authProvider.getPasswordField());

    assertNotNull(userpassword);

    switch (authProvider.getHashStrategy().getSaltStyle()) {
    case NO_SALT:
      assertSame(password, userpassword);
      break;
    default:
      assertNotSame(password, userpassword);

    }
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
  private boolean initOneUser(User user, CountDownLatch latch) throws Exception {
    CountDownLatch intLatch = new CountDownLatch(1);
    final StringBuffer buffer = new StringBuffer();
    getMongoService().save(authProvider.getCollectionName(), user.principal(), res -> {
      if (res.succeeded()) {
        log.info("user added: " + user.principal().getString(authProvider.getUsernameField()));
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

  public JsonObject createAuthInfo(String username, String password) {
    JsonObject authInfo = new JsonObject();
    authInfo.put(authProvider.getUsernameField(), username).put(authProvider.getPasswordField(), password);
    return authInfo;
  }

}
