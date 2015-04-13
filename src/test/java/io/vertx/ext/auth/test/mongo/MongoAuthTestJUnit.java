package io.vertx.ext.auth.test.mongo;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.mongo.MongoAuthProvider;
import io.vertx.ext.auth.mongo.MongoAuthService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runners.model.InitializationError;

/**
 * @author mremme
 */

public class MongoAuthTestJUnit extends MongoBaseTest {
  private static final Logger log = LoggerFactory.getLogger(MongoAuthTestJUnit.class);

  protected AuthService       authService;

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
  }

  @Override
  protected void tearDown() throws Exception {
    authService.stop();
    super.tearDown();
  }

  /**
   * Test a user with unique username and password
   */
  @Test
  public void testLoginUniqueUser() throws Exception {
    initAuthService();
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
  public void testLoginDoublette1() throws Exception {
    initAuthService();
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
   * 
   * @throws Exception
   */
  @Test
  public void testLoginDoublette2() throws Exception {
    initAuthService();
    JsonObject credentials = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, "Doublette").put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, "ps2");
    authService.login(credentials, onFailure(thr -> {
      assertNotNull(thr);
      testComplete();
    }));
    await();

  }

  @Test
  public void testHasRole() throws Exception {
    initAuthService();
    loginThen(sessID -> this.<Boolean> executeTwice(handler -> authService.hasRole(sessID, "morris_dancer", handler),
        res -> {
          assertTrue(res.succeeded());
          assertTrue(res.result());
        }));

    await();
  }

  @Test
  public void testHasRoleNotLoggedIn() throws Exception {
    initAuthService();
    this.<Boolean> executeTwice(handler -> authService.hasRole("uqhwdihuqwd", "morris_dancer", handler), res -> {
      assertFalse(res.succeeded());
      assertEquals("not logged in", res.cause().getMessage());
    });
    await();
  }

  @Test
  public void testNotHasRole() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean> executeTwice(handler -> authService.hasRole(sessID, "manager", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasRoles() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
      this.<Boolean> executeTwice(handler -> authService.hasRoles(sessID, roles, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasRolesNotLoggedIn() throws Exception {
    initAuthService();
    Set<String> roles = new HashSet<>(Arrays.asList("morris_dancer", "developer"));
    authService.hasRoles("uhqwdihu", roles, onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasRoles() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> roles = new HashSet<>(Arrays.asList("administrator", "developer"));
      this.<Boolean> executeTwice(handler -> authService.hasRoles(sessID, roles, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean> executeTwice(handler -> authService.hasPermission(sessID, "do_actual_work", handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissionNotLoggedIn() throws Exception {
    initAuthService();
    this.<Boolean> executeTwice(handler -> authService.hasPermission("uqhwdihuqwd", "morris_dancer", handler), res -> {
      assertFalse(res.succeeded());
      assertEquals("not logged in", res.cause().getMessage());
    });
    await();
  }

  @Test
  public void testNotHasPermission() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      this.<Boolean> executeTwice(handler -> authService.hasPermission(sessID, "play_golf", handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissions() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
      this.<Boolean> executeTwice(handler -> authService.hasPermissions(sessID, permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertTrue(res.result());
      });
    });
    await();
  }

  @Test
  public void testHasPermissionsNotLoggedIn() throws Exception {
    initAuthService();
    Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "bang_sticks"));
    authService.hasPermissions("uhqwdihu", permissions, onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testNotHasPermissions() throws Exception {
    initAuthService();
    loginThen(sessID -> {
      Set<String> permissions = new HashSet<>(Arrays.asList("do_actual_work", "eat_cheese"));
      this.<Boolean> executeTwice(handler -> authService.hasPermissions(sessID, permissions, handler), res -> {
        assertTrue(res.succeeded());
        assertFalse(res.result());
      });
    });
    await();
  }

  @Test
  public void testLoginNoTimeout() throws Exception {
    initAuthService(100);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 5000, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      vertx.setTimer(1000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(hasRole -> {
          assertTrue(hasRole);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testRefreshSession() throws Exception {
    initAuthService(500);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 200, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.refreshLoginSession(sessionID, res -> {
        assertTrue(res.succeeded());
      }));
      vertx.setTimer(2000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(res -> {
          assertTrue(res);
          vertx.cancelTimer(pid);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testRefreshSessionHasRole() throws Exception {
    initAuthService(500);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 200, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.hasRole(sessionID, "morris_dancer", res -> {
        assertTrue(res.succeeded());
      }));
      vertx.setTimer(2000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(res -> {
          assertTrue(res);
          vertx.cancelTimer(pid);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testRefreshSessionHasPermission() throws Exception {
    initAuthService(500);
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.loginWithTimeout(credentials, 200, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      long pid = vertx.setPeriodic(100, tid -> authService.hasPermission(sessionID, "bang_sticks", res -> {
        assertTrue(res.succeeded());
      }));
      vertx.setTimer(2000, tid -> {
        authService.hasRole(sessionID, "morris_dancer", onSuccess(res -> {
          assertTrue(res);
          vertx.cancelTimer(pid);
          testComplete();
        }));
      });
    }));
    await();
  }

  @Test
  public void testTouchSessionNotLoggedIn() throws Exception {
    initAuthService();
    authService.refreshLoginSession("qijsoiqsj", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  @Test
  public void testLogout() throws Exception {
    initAuthService();
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      authService.logout(sessionID, onSuccess(v -> {
        authService.hasRole(sessionID, "morris_dancer", onFailure(thr -> {
          assertNotNull(thr);
          assertEquals("not logged in", thr.getMessage());
          testComplete();
        }));
      }));
    }));
    await();
  }

  @Test
  public void testLogoutNotLoggedIn() throws Exception {
    initAuthService();
    authService.logout("qijsoiqsj", onFailure(thr -> {
      assertNotNull(thr);
      assertEquals("not logged in", thr.getMessage());
      testComplete();
    }));
    await();
  }

  /*
   * preparation methods
   */

  protected List<JsonObject> createUserList() {
    List<JsonObject> users = new ArrayList<JsonObject>();
    users.add(createUser("Michael", "ps1"));
    users.add(createUser("Doublette", "ps1"));
    users.add(createUser("Doublette", "ps2"));
    users.add(createUser("Doublette", "ps2"));

    users.add(createUser("tim", "sausages", Arrays.asList("morris_dancer", "superadmin", "developer"),
        Arrays.asList("do_actual_work", "bang_sticks")));
    return users;
  }

  private void initAuthService() throws Exception {
    if (authService == null) {
      log.info("initAuthService");
      authService = new MongoAuthService(vertx, getMongoService(), createAuthServiceConfig());
    }
  }

  private void initAuthService(long reaperPeriod) throws Exception {
    if (authService == null) {
      log.info("initAuthService");
      authService = new MongoAuthService(vertx, getMongoService(), createAuthServiceConfig())
          .setReaperPeriod(reaperPeriod);
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

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  protected JsonObject createUser(String username, String password) {
    return createUser(username, password, null, null);
  }

  /**
   * Creates a user as {@link JsonObject}
   * 
   * @param username
   * @param password
   * @return
   */
  protected JsonObject createUser(String username, String password, List<String> roles, List<String> permissions) {
    JsonObject user = new JsonObject().put(MongoAuthProvider.DEFAULT_USERNAME_FIELD, username).put(
        MongoAuthProvider.DEFAULT_PASSWORD_FIELD, password);

    List<String> completeList = new ArrayList();
    if (roles != null) {
      completeList.addAll(roles);
    }
    if (permissions != null) {
      completeList.addAll(permissions);
    }
    if (!completeList.isEmpty()) {
      user.put(MongoAuthProvider.DEFAULT_ROLE_FIELD, new JsonArray(completeList));
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

  private void loginThen(Consumer<String> runner) throws Exception {
    JsonObject credentials = new JsonObject().put("username", "tim").put("password", "sausages");
    authService.login(credentials, onSuccess(sessionID -> {
      assertNotNull(sessionID);
      runner.accept(sessionID);
    }));
  }

  private <T> void executeTwice(Consumer<Handler<AsyncResult<T>>> action, Consumer<AsyncResult<T>> resultConsumer) {
    action.accept(res -> {
      resultConsumer.accept(res);
      action.accept(res2 -> {
        resultConsumer.accept(res);
        testComplete();
      });
    });
  }

}
