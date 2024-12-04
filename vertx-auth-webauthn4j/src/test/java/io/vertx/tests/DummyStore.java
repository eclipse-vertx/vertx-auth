package io.vertx.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import io.vertx.core.Future;
import io.vertx.ext.auth.webauthn4j.Authenticator;
import io.vertx.ext.auth.webauthn4j.CredentialStorage;

public class DummyStore implements CredentialStorage {

  private final List<Authenticator> database = new ArrayList<>();

  public DummyStore add(Authenticator authenticator) {
    this.database.add(authenticator);
    return this;
  }

  public void clear() {
    database.clear();
  }

  @Override
  public Future<List<Authenticator>> find(String userName, String credentialId) {
    return Future.succeededFuture(
      database.stream()
        .filter(entry -> {
          if (userName != null) {
            return userName.equals(entry.getUsername());
          }
          if (credentialId != null) {
            return credentialId.equals(entry.getCredID());
          }
          // This is a bad query! both username and credID are null
          return false;
        })
        .collect(Collectors.toList())
    );
  }

  @Override
  public Future<Void> storeCredential(Authenticator authenticator) {
    long found = database.stream()
        .filter(entry -> authenticator.getCredID().equals(entry.getCredID()))
        .count();
    if (found != 0) {
      return Future.failedFuture("Authenticator already exists");
    } else {
      // this is a new authenticator, make sure the user does not already exist, otherwise we risk adding
      // third-person credentials to an existing user
      long existingUser = database.stream()
          .filter(entry -> authenticator.getUsername().equals(entry.getUsername()))
          .count();
      if(existingUser == 0) {
        database.add(authenticator);
        return Future.succeededFuture();
      } else {
        return Future.failedFuture("User already exists");
      }
    }
  }

  @Override
  public Future<Void> updateCounter(Authenticator authenticator) {
    long updated = database.stream()
        .filter(entry -> authenticator.getCredID().equals(entry.getCredID()))
        .peek(entry -> {
          // update existing counter
          entry.setCounter(authenticator.getCounter());
        }).count();
    if (updated > 0) {
      return Future.succeededFuture();
    } else {
      return Future.failedFuture("Could not find authenticator");
    }
  }
}
