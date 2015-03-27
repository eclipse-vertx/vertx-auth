package io.vertx.ext.auth.test.mongo;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.auth.mongo.MongoAuthProvider;
import io.vertx.ext.mongo.MongoService;
import io.vertx.ext.unit.TestContext;
import io.vertx.test.core.VertxTestBase;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;

/**
 * Creates the local mongodb and the MongoService
 * 
 * @author mremme
 */

public class MongoTestBase extends VertxTestBase {
  private static final Logger     log           = LoggerFactory.getLogger(MongoTestBase.class);

  protected Vertx                 vertx         = Vertx.vertx();
  private static MongodExecutable exe;
  private MongoService            mongoService;
  private Handler<TestContext>    beforeHandler = new BeforeHandler();
  private Handler<TestContext>    afterHandler  = new AfterHandler();

  public MongoTestBase() {
  }

  /**
   * Returns the handler which is executed before a suite
   * 
   * @return
   */
  public Handler<TestContext> getBeforeHandler() {
    return beforeHandler;
  }

  /**
   * Returns the handler which is executed after a suite
   * 
   * @return
   */
  public Handler<TestContext> getAfterHandler() {
    return afterHandler;
  }

  /**
   * @return the mongoService
   */
  public MongoService getMongoService() {
    return mongoService;
  }

  private void init(TestContext context) {
    try {
      startMongo();
      initMongoService(context);
      initDemoData(context);
    } catch (Exception e) {
      context.fail(e);
    }
  }

  private void shutdown(TestContext context) {
    stopMongo();
  }

  private void initMongoService(TestContext context) throws Exception {
    JsonObject config = getConfig();
    mongoService = MongoService.create(vertx, config);
    mongoService.start();
    dropCollections(context);
  }

  protected void initDemoData(TestContext context) throws Exception {
    initTestUsers(context);
  }

  protected void initTestUsers(TestContext context) throws Exception {

    List<JsonObject> users = createUserList();
    CountDownLatch latch = new CountDownLatch(users.size());

    for (JsonObject user : users) {
      initOneUser(context, user, latch);
    }
    latch.await();

    CountDownLatch latch2 = new CountDownLatch(1);
    mongoService.count(MongoAuthProvider.DEFAULT_COLLECTION_NAME, new JsonObject(), result -> {
      log.info("count users: " + result.result());
      Long count = result.result();
      context.assertTrue(count > 0, "No users added");
      latch2.countDown();
    });
    latch2.await();
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

  private void initOneUser(TestContext context, JsonObject user, CountDownLatch latch) {
    mongoService.save(MongoAuthProvider.DEFAULT_COLLECTION_NAME, user, res -> {
      if (res.succeeded()) {
        log.info("user added: " + user.getString(MongoAuthProvider.DEFAULT_USERNAME_FIELD));
        latch.countDown();
      } else {
        context.fail(res.cause());
      }
    });
  }

  /**
   * drops the userdefined collections to restart the database
   * 
   * @param context
   */
  protected void dropCollections(TestContext context) {

    mongoService.getCollections(result -> {
      if (result.succeeded()) {
        List<String> toDrop = getOurCollections(result.result());
        if (!toDrop.isEmpty()) {
          CountDownLatch latch = new CountDownLatch(toDrop.size());

          for (String collection : toDrop) {
            dropCollection(context, collection, latch);
          }
          try {
            latch.await();
          } catch (Exception e) {
            context.fail(e);
          }
        }
      } else {
        context.fail(result.cause());
      }

    });
  }

  protected void dropCollection(TestContext context, String collection, CountDownLatch latch) {
    mongoService.dropCollection(collection, result -> {
      if (result.succeeded()) {
        log.info("drop collection done: " + collection);
        latch.countDown();
      } else {
        context.fail(result.cause());
      }
    });

  }

  protected List<String> getOurCollections(List<String> colls) {
    List<String> ours = new ArrayList<>();
    for (String coll : colls) {
      log.info("found collection: " + coll);
      if (isOurCollection(coll)) {
        ours.add(coll);
      }
    }
    return ours;
  }

  protected boolean isOurCollection(String collectionName) {
    return collectionName.startsWith("ext-mongo") || collectionName.equals(MongoAuthProvider.DEFAULT_COLLECTION_NAME);
  }

  private void startMongo() throws Exception {
    if (getConnectionString() == null) {
      IMongodConfig config = new MongodConfigBuilder().version(Version.Main.PRODUCTION)
          .net(new Net(27018, Network.localhostIsIPv6())).build();
      exe = MongodStarter.getDefaultInstance().prepare(config);
      exe.start();
    }
  }

  private void stopMongo() {
    if (exe != null) {
      exe.stop();
    }
  }

  protected static String getConnectionString() {
    return getProperty("connection_string");
  }

  protected static String getDatabaseName() {
    return getProperty("db_name");
  }

  protected static String getProperty(String name) {
    String s = System.getProperty(name);
    if (s != null) {
      s = s.trim();
      if (s.length() > 0) {
        return s;
      }
    }
    return null;
  }

  protected JsonObject getConfig() {
    JsonObject config = new JsonObject();
    String connectionString = getConnectionString();
    if (connectionString != null) {
      config.put("connection_string", connectionString);
    } else {
      config.put("connection_string", "mongodb://localhost:27018");
    }
    String databaseName = getDatabaseName();
    if (databaseName != null) {
      config.put("db_name", databaseName);
    }
    return config;
  }

  class BeforeHandler implements Handler<TestContext> {

    /*
     * (non-Javadoc)
     * @see io.vertx.core.Handler#handle(java.lang.Object)
     */
    @Override
    public void handle(TestContext context) {
      init(context);
    }

  }

  class AfterHandler implements Handler<TestContext> {

    /*
     * (non-Javadoc)
     * @see io.vertx.core.Handler#handle(java.lang.Object)
     */
    @Override
    public void handle(TestContext context) {
      shutdown(context);
    }

  }

}
