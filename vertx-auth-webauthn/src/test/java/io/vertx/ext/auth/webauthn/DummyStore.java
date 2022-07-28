package io.vertx.ext.auth.webauthn;

import io.vertx.core.Future;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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
    if (query.getUserName() == null && query.getCredID() == null && query.getUserId() == null) {
      return Future.failedFuture(new IllegalArgumentException("Bad authenticator query! All conditions were null"));
    }

    return Future.succeededFuture(
      database.stream()
        .filter(entry -> {
          boolean matches = true;
          if (query.getUserName() != null) {
            matches = query.getUserName().equals(entry.getUserName());
          }
          if (query.getCredID() != null) {
            matches = matches || query.getCredID().equals(entry.getCredID());
          }
          if (query.getUserId() != null) {
            matches = matches || query.getUserId().equals(entry.getUserId());
          }

          return matches;
        })
        .collect(Collectors.toList())
    );
  }

  public Future<Void> store(Authenticator authenticator) {
    System.out.println(authenticator);

    long updated = database.stream()
      .filter(entry -> authenticator.getCredID().equals(entry.getCredID()))
      .peek(entry -> {
        // update existing counter
        entry.setCounter(authenticator.getCounter());
      }).count();

    if (updated > 0) {
      return Future.succeededFuture();
    } else {
      database.add(authenticator);
      return Future.succeededFuture();
    }
  }
}
