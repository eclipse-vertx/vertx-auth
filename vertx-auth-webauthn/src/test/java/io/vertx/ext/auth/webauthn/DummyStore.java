package io.vertx.ext.auth.webauthn;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.ext.auth.webauthn.store.Authenticator;
import io.vertx.ext.auth.webauthn.store.AuthenticatorStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class DummyStore implements AuthenticatorStore {

  private final List<Authenticator> database;

  public DummyStore() {
    database = new ArrayList<>();
  }

  public DummyStore(Authenticator... database) {
    this.database = new ArrayList<>();
    this.database.addAll(Arrays.asList(database));
  }

  @Override
  public AuthenticatorStore getAuthenticatorsByUserName(String name, Handler<AsyncResult<List<Authenticator>>> handler) {
    handler.handle(Future.succeededFuture(
      database.stream()
        .filter(entry -> name.equals(entry.getUserName()))
        .collect(Collectors.toList())
    ));
    return this;
  }

  @Override
  public AuthenticatorStore getAuthenticatorsByCredId(String credId, Handler<AsyncResult<List<Authenticator>>> handler) {
    handler.handle(Future.succeededFuture(
      database.stream()
        .filter(entry -> credId.equals(entry.getCredID()))
        .collect(Collectors.toList())
    ));
    return this;
  }

  @Override
  public AuthenticatorStore update(Authenticator authenticator, boolean upsert, Handler<AsyncResult<Void>> handler) {

    long updated = database.stream()
      .filter(entry -> authenticator.getCredID().equals(entry.getCredID()))
      .peek(entry -> {
        // update existing counter
        entry.setCounter(authenticator.getCounter());
      }).count();

    if (updated > 0) {
      handler.handle(Future.succeededFuture());
    } else {
      if (upsert) {
        database.add(authenticator);
        handler.handle(Future.succeededFuture());
      } else {
        handler.handle(Future.failedFuture("Nothing updated!"));
      }
    }
    return this;
  }
}
