package io.vertx.tests;

import io.vertx.core.Future;
import io.vertx.ext.auth.webauthn.Authenticator;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DummyStore {

  private final List<Authenticator> database = new ArrayList<>();

  public DummyStore add(Authenticator authenticator) {
    this.database.add(authenticator);
    return this;
  }

  public void clear() {
    database.clear();
  }

  public Future<List<Authenticator>> fetch(Authenticator query) {
    return Future.succeededFuture(
      database.stream()
        .filter(entry -> {
          if (query.getUserName() != null) {
            return query.getUserName().equals(entry.getUserName());
          }
          if (query.getCredID() != null) {
            return query.getCredID().equals(entry.getCredID());
          }
          // This is a bad query! both username and credID are null
          return false;
        })
        .collect(Collectors.toList())
    );
  }

  public Future<Void> store(Authenticator authenticator) {
    long updated = database.stream()
      .filter(entry -> authenticator.getCredID().equals(entry.getCredID()))
      .peek(entry -> {
        // update existing counter
        entry.setCounter(authenticator.getCounter());
      }).count();

    if (updated > 0) {
      return Future.succeededFuture();
    } else {
      // this is a new authenticator, make sure the user does not already exist, otherwise we risk adding 
      // third-person credentials to an existing user
      long existingUser = database.stream()
          .filter(entry -> authenticator.getUserName().equals(entry.getUserName()))
          .count();
      if(existingUser == 0) {
        database.add(authenticator);
        return Future.succeededFuture();
      } else {
        return Future.failedFuture("User already exists");
      }
    }
  }
}
