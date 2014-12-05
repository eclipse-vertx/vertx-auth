package io.vertx.ext.auth;

import io.vertx.core.AbstractVerticle;
import io.vertx.serviceproxy.ProxyHelper;

/**
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class AuthServiceVerticle extends AbstractVerticle {

  AuthService service;

  @Override
  public void start() throws Exception {

    // Create the service object
    service = AuthService.create(vertx, AuthRealmType.PROPERTIES, config());

    // And register it on the event bus against the configured address
    String address = config().getString("address");
    if (address == null) {
      throw new IllegalStateException("address field must be specified in config for service verticle");
    }
    ProxyHelper.registerService(AuthService.class, vertx, service, address);

    // Start it
    service.start();
  }

  @Override
  public void stop() throws Exception {
    service.stop();
  }
}
