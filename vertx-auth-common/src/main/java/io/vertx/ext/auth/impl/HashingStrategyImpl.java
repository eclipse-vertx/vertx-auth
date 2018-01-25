package io.vertx.ext.auth.impl;

import io.vertx.ext.auth.HashingAlgorithm;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.impl.hash.HashString;

import java.util.HashMap;
import java.util.Map;

public class HashingStrategyImpl implements HashingStrategy {

  private final Map<String, HashingAlgorithm> algorithms = new HashMap<>();

  public void add(HashingAlgorithm algorithm) {
    algorithms.put(algorithm.id(), algorithm);
  }

  @Override
  public String hash(String id, Map<String, String> params, byte[] salt, String password) {
    HashingAlgorithm algorithm = algorithms.get(id);

    if (algorithm == null) {
      throw new RuntimeException(id +  " algorithm is not available.");
    }

    byte[] hash = algorithm.hash(params, password, salt);
    // encode to the expected format
    return HashString.encode(algorithm, params, salt, hash);
  }

  @Override
  public boolean verify(String hash, String password) {
    // missing data
    if (hash == null || password == null) {
      return false;
    }

    final HashString hashString = new HashString(hash);

    HashingAlgorithm algorithm = algorithms.get(hashString.id());

    if (algorithm == null) {
      // TODO: log missing algorithm as a warning
      return false;
    }

    if (hashString.hash() == null) {
      return false;
    }

    byte[] hasha = hashString.hash();
    byte[] hashb = algorithm.hash(hashString.params(), password, hashString.salt());

    int diff = hasha.length ^ hashb.length;
    for (int i = 0; i < hasha.length && i < hashb.length; i++) {
      diff |= hasha[i] ^ hashb[i];
    }

    return diff == 0;
  }
}
