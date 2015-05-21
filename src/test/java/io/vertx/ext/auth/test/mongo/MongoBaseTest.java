package io.vertx.ext.auth.test.mongo;

import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.impl.LoggerFactory;
import io.vertx.ext.mongo.MongoService;
import io.vertx.test.core.TestUtils;
import io.vertx.test.core.VertxTestBase;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;

/**
 * @author mremme
 */

public abstract class MongoBaseTest extends VertxTestBase {
  private static final Logger     log          = LoggerFactory.getLogger(MongoBaseTest.class);

  public static final String      TABLE_PREFIX = "TestMongo_";

  private static MongodExecutable exe;
  private MongoService            mongoService;

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

  @BeforeClass
  public static void startMongo() throws Exception {
    if (getConnectionString() == null) {
      IMongodConfig config = new MongodConfigBuilder().version(Version.Main.PRODUCTION)
          .net(new Net(27018, Network.localhostIsIPv6())).build();
      exe = MongodStarter.getDefaultInstance().prepare(config);
      exe.start();
    }
  }

  @AfterClass
  public static void stopMongo() {
    if (exe != null) {
      exe.stop();
    }
  }

  /**
   * If instance of MongoService is null, initialization is performed
   * 
   * @return
   * @throws Exception
   */
  public MongoService getMongoService() throws Exception {
    if (mongoService == null) {
      initMongoService();
      initDemoData();
    }
    return mongoService;
  }

  private void initMongoService() throws Exception {
    JsonObject config = getConfig();
    mongoService = MongoService.create(vertx, config);
    mongoService.start();
    CountDownLatch latch = new CountDownLatch(1);
    dropCollections(latch);
    awaitLatch(latch);

  }

  /**
   * Initialize the demo data needed for the tests
   * 
   * @throws Exception
   */
  public abstract void initDemoData() throws Exception;

  /**
   * Create a random Name of a collection
   * 
   * @return
   */
  public String randomCollection() {
    return createCollectionName(TestUtils.randomAlphaString(20));
  }

  /**
   * Create a name of a collection by adding a certain suffix. All Collections with this suffix will be cleared by start
   * of the test class
   * 
   * @param name
   * @return
   */
  public String createCollectionName(String name) {
    return TABLE_PREFIX + name;
  }

  protected static JsonObject getConfig() {
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

  protected static List<String> getOurCollections(List<String> colls) {
    List<String> ours = new ArrayList<>();
    for (String coll : colls) {
      if (coll.startsWith(TABLE_PREFIX)) {
        ours.add(coll);
      }
    }
    return ours;
  }

  protected void dropCollections(CountDownLatch latch) {
    // Drop all the collections in the db
    mongoService.getCollections(onSuccess(list -> {
      AtomicInteger collCount = new AtomicInteger();
      List<String> toDrop = getOurCollections(list);
      int count = toDrop.size();
      if (!toDrop.isEmpty()) {
        for (String collection : toDrop) {
          mongoService.dropCollection(collection, onSuccess(v -> {
            if (collCount.incrementAndGet() == count) {
              latch.countDown();
            }
          }));
        }
      } else {
        latch.countDown();
      }
    }));
  }

}
