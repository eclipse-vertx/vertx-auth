package io.vertx.ext.auth.mongo;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthService;
import io.vertx.ext.auth.impl.AuthServiceImpl;
import io.vertx.ext.mongo.MongoService;

/**
 * An AuthService which is using MongoDb as a source
 * 
 * @author mremme
 */

public class MongoAuthService extends AuthServiceImpl {
  private Vertx vertx;

  /**
   * @param vertx
   * @param config
   * @param provider
   */
  public MongoAuthService(Vertx vertx, String serviceName, JsonObject config) {
    super(vertx, new MongoAuthProvider(vertx, serviceName, config));
    this.vertx = vertx;
  }

  /**
   * @param vertx
   * @param config
   * @param provider
   */
  public MongoAuthService(Vertx vertx, MongoService service, JsonObject config) {
    super(vertx, new MongoAuthProvider(vertx, service, config));
    this.vertx = vertx;
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.impl.AuthServiceImpl#logout(java.lang.String, io.vertx.core.Handler)
   */
  @Override
  public AuthService logout(String loginID, Handler<AsyncResult<Void>> resultHandler) {
    vertx.getOrCreateContext().remove(MongoAuthProvider.CURRENT_PRINCIPAL_PROPERTY);
    return super.logout(loginID, resultHandler);
  }

}
