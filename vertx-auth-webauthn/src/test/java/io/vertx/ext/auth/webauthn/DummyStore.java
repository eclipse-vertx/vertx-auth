package io.vertx.ext.auth.webauthn;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DummyStore implements AuthStore {

  public static class StoreEntry {
    String username;

    String credID;
    String publicKey;
    long counter;

    public String getUsername() {
      return username;
    }

    public StoreEntry setUsername(String username) {
      this.username = username;
      return this;
    }

    public String getCredID() {
      return credID;
    }

    public StoreEntry setCredID(String credID) {
      this.credID = credID;
      return this;
    }

    public String getPublicKey() {
      return publicKey;
    }

    public StoreEntry setPublicKey(String publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    public long getCounter() {
      return counter;
    }

    public StoreEntry setCounter(long counter) {
      this.counter = counter;
      return this;
    }

    JsonObject toJson() {
      return new JsonObject()
        .put("credID", credID)
        .put("publicKey", publicKey)
        .put("counter", counter);
    }
  }

  private final List<StoreEntry> database;

  public DummyStore() {
    database = new ArrayList<>();
  }

  public DummyStore(List<StoreEntry> database) {
    this.database = database;
  }

  @Override
  public AuthStore getUserCredentialsByName(String username, Handler<AsyncResult<List<JsonObject>>> handler) {

    handler.handle(Future.succeededFuture(
      database.stream()
        .filter(entry -> username.equals(entry.username))
        .map(StoreEntry::toJson)
        .collect(Collectors.toList())
    ));

    return this;
  }

  @Override
  public AuthStore getUserCredentialsById(String id, Handler<AsyncResult<List<JsonObject>>> handler) {
    handler.handle(Future.succeededFuture(
      database.stream()
        .filter(entry -> id.equals(entry.credID))
        .map(StoreEntry::toJson)
        .collect(Collectors.toList())
    ));

    return this;
  }

  @Override
  public AuthStore updateUserCredential(String id, JsonObject data, boolean upsert, Handler<AsyncResult<Void>> handler) {

    long updated = database.stream()
      .filter(entry -> id.equals(entry.credID))
      .peek(entry -> {
        // update existing credential
        entry.publicKey = data.getString("publicKey");
        entry.counter = data.getLong("counter", 0L);
      }).count();

    if (updated > 0) {
      handler.handle(Future.succeededFuture());
    } else {
      if (upsert) {
        database.add(
          new StoreEntry()
            .setUsername(data.getString("username"))
            .setCredID(data.getString("credID"))
            .setPublicKey(data.getString("publicKey"))
            .setCounter(data.getLong("counter", 0L))
        );
        handler.handle(Future.succeededFuture());
      } else {
        handler.handle(Future.failedFuture("Nothing updated!"));
      }
    }
    return this;
  }
}
