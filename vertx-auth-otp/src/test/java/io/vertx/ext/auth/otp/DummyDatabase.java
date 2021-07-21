package io.vertx.ext.auth.otp;

import io.vertx.core.Future;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DummyDatabase {

  private final Map<String, Authenticator> DB = new ConcurrentHashMap<>();

  public Future<Authenticator> fetch(String id) {
    if (DB.containsKey(id)) {
      return Future.succeededFuture(DB.get(id));
    } else {
      return Future.succeededFuture();
    }
  }

  public Future<Void> upsert(Authenticator authenticator) {
    DB.put(authenticator.getIdentifier(), authenticator);
    return Future.succeededFuture();
  }

  public DummyDatabase fixture(Authenticator authenticator) {
    DB.put(authenticator.getIdentifier(), authenticator);
    return this;
  }
}
