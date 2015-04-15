package io.vertx.ext.auth.mongo;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.ext.mongo.MongoService;

/**
 * An AuthService which is using MongoDb as a source
 * 
 * @author mremme
 */

public class MongoAuthService extends AuthServiceImpl {

  /**
   * @param vertx
   * @param config
   * @param provider
   */
  public MongoAuthService(Vertx vertx, String serviceName, JsonObject config) {
    super(vertx, config, new MongoAuthProvider(vertx, serviceName));
  }

  /**
   * @param vertx
   * @param config
   * @param provider
   */
  public MongoAuthService(Vertx vertx, MongoService service, JsonObject config) {
    super(vertx, config, new MongoAuthProvider(vertx, service));
  }

}
