/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.auth.mongo.test;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.mongo.MongoAuthentication;
import io.vertx.ext.auth.mongo.MongoAuthenticationOptions;
import io.vertx.ext.auth.mongo.MongoAuthorizationOptions;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.test.core.VertxTestBase;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author mremme
 */

public abstract class MongoBaseTest extends VertxTestBase {

  private static final Logger log = LoggerFactory.getLogger(MongoBaseTest.class);

  public static final String TABLE_PREFIX = "TestMongo_";

  private static MongodExecutable exe;
  private MongoClient mongoClient;

  /**
   * Get the connection String for the mongo db
   *
   * @return
   */
  protected static String getConnectionString() {
    return getProperty("connection_string");
  }

  /**
   * Get the name of the database to be used
   *
   * @return
   */
  protected static String getDatabaseName() {
    return getProperty("db_name");
  }

  /**
   * Get a property with the given key
   *
   * @param name
   *          the key of the property to be fetched
   * @return a valid value or null
   */
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
    String uri = getConnectionString();
    if (uri == null ) {
      Version.Main version = Version.Main.V3_4;
      int port = 27018;
      System.out.println("Starting Mongo " + version + " on port " + port);
      IMongodConfig config = new MongodConfigBuilder().
        version(version).
        net(new Net(port, Network.localhostIsIPv6())).
        build();
      exe = MongodStarter.getDefaultInstance().prepare(config);
      exe.start();
    } else {
      System.out.println("Using existing Mongo " + uri);
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
   * @return the current instance of {@link MongoClient}
   * @throws Exception
   *           any Exception by submethods
   */
  public MongoClient getMongoClient() throws Exception {
    if (mongoClient == null) {
      initMongoClient();
    }
    return mongoClient;
  }

  private void initMongoClient() throws Exception {
    CountDownLatch latch = new CountDownLatch(1);
    System.out.println(getConfig().encode());
    mongoClient = MongoClient.createShared(vertx, getConfig());
    dropCollections(latch);
    awaitLatch(latch);
  }

  /**
   * Create a name of a collection by adding a certain suffix. All Collections with this suffix will be cleared by start
   * of the test class
   *
   * @param name
   *          the pure name of the collection
   * @return the name of the collection extended by the defined {@link #TABLE_PREFIX}
   */
  public String createCollectionName(String name) {
    return TABLE_PREFIX + name;
  }

  /**
   * Creates a config file for a mongo db
   *
   * @return the prepared config file with the connection string and the database name to be used
   */
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

  /**
   * Extracts only those collections, which are starting with the prefix {@link #TABLE_PREFIX}
   *
   * @param colls
   *          a list of collection names
   * @return a list of collections, which start with {@link #TABLE_PREFIX}
   */
  protected static List<String> getOurCollections(List<String> colls) {
    List<String> ours = new ArrayList<>();
    for (String coll : colls) {
      if (coll.startsWith(TABLE_PREFIX)) {
        ours.add(coll);
      }
    }
    return ours;
  }

  /**
   * Method drops all collections which are starting with the prefix {@link #TABLE_PREFIX}
   *
   * @param latch
   *          the latch to be used
   */
  protected void dropCollections(CountDownLatch latch) {
    // Drop all the collections in the db
    mongoClient.getCollections(onSuccess(list -> {
      AtomicInteger collCount = new AtomicInteger();
      List<String> toDrop = getOurCollections(list);
      int count = toDrop.size();
      if (!toDrop.isEmpty()) {
        for (String collection : toDrop) {
          mongoClient.dropCollection(collection, onSuccess(v -> {
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

  protected Future<String> insertUser(MongoAuthentication authenticationProvider, MongoAuthenticationOptions authenticationOptions, String username, String password) throws Exception {

    String hashedPassword = authenticationProvider.hash("pbkdf2", "somesalt", password);

    JsonObject user = new JsonObject();
    user.put(authenticationOptions.getUsernameField(), username);
    user.put(authenticationOptions.getPasswordField(), hashedPassword);

    Promise<String> promise = Promise.promise();
    getMongoClient().save(authenticationOptions.getCollectionName(), user, promise);
    return promise.future();
  }

  protected boolean verifyUserData(MongoAuthenticationOptions authenticationOptions) throws Exception {
    final StringBuffer buffer = new StringBuffer();
    CountDownLatch intLatch = new CountDownLatch(1);
    String collectionName = authenticationOptions.getCollectionName();
    log.info("verifyUserData in " + collectionName);
    getMongoClient().find(collectionName, new JsonObject(), res -> {
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

  protected boolean verifyRoleData(MongoAuthorizationOptions authorizationOptions) throws Exception {
    final StringBuffer buffer = new StringBuffer();
    CountDownLatch intLatch = new CountDownLatch(1);
    String collectionName = authorizationOptions.getRoleCollectionName();
    log.info("verifyRoleData in " + collectionName);
    getMongoClient().find(collectionName, new JsonObject(), res -> {
      if (res.succeeded()) {
        log.info(res.result().size() + " roles found: " + res.result());

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
