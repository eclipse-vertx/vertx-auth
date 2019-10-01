package io.vertx.ext.auth.webauthn;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthStore;

import java.util.ArrayList;
import java.util.List;

public class DummyStore implements AuthStore {

  private final JsonObject database;

  public DummyStore() {
    this(new JsonObject());
  }

  public DummyStore(JsonObject database) {
    this.database = database;
  }

  @Override
  public AuthStore getUserCredentials(String id, Handler<AsyncResult<List<JsonObject>>> handler) {
    JsonArray array = database.getJsonArray(id);
    if (array != null) {
      List<JsonObject> credentials = new ArrayList<>();
      for (Object o : array) {
        credentials.add((JsonObject) o);
      }
      handler.handle(Future.succeededFuture(credentials));
    } else {
      handler.handle(Future.succeededFuture());
    }
    return this;
  }

  @Override
  public AuthStore updateUserCredential(String id, JsonObject data, Handler<AsyncResult<Void>> handler) {
    JsonArray array = database.getJsonArray(id);
    if (array != null) {
      for (Object o : array) {
        JsonObject json = (JsonObject) o;
        if (json.getString("credID").equals(data.getString("credID"))) {
          // update existing credential
          json.mergeIn(data);
          handler.handle(Future.succeededFuture());
          return this;
        }
      }
      // add a new credential to the chain
      array.add(data);
      handler.handle(Future.succeededFuture());
    } else {
      // add a newly credential
      database.put(id, new JsonArray().add(data));
      handler.handle(Future.succeededFuture());
    }
    return this;
  }
}
