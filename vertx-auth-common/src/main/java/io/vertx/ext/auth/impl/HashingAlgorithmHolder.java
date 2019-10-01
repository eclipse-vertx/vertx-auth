package io.vertx.ext.auth.impl;

import io.vertx.ext.auth.HashingAlgorithm;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public final class HashingAlgorithmHolder {

  private static final Map<String, HashingAlgorithm> BY_ID = new HashMap<>();
  private static final Map<String, HashingAlgorithm> BY_ALGORITHM = new HashMap<>();

  static {
    ServiceLoader<HashingAlgorithm> serviceLoader = ServiceLoader.load(HashingAlgorithm.class);

    for (HashingAlgorithm algorithm : serviceLoader) {
      BY_ID.put(algorithm.id(), algorithm);
      BY_ALGORITHM.put(algorithm.algorithm(), algorithm);
    }
  }

  public static HashingAlgorithm getById(String id) {
    final HashingAlgorithm hashingAlgorithm = BY_ID.get(id);
    if (hashingAlgorithm == null) {
      throw new IllegalArgumentException("No such id available: " + id);
    }
    return hashingAlgorithm;
  }

  public static HashingAlgorithm getByAlgorithm(String id) {
    final HashingAlgorithm hashingAlgorithm = BY_ALGORITHM.get(id);
    if (hashingAlgorithm == null) {
      throw new IllegalArgumentException("No such algorithm available: " + id);
    }
    return hashingAlgorithm;
  }

  static boolean containsId(String id) {
    return BY_ID.containsKey(id);
  }

  static void putId(String id, HashingAlgorithm algorithm) {
    BY_ID.put(id, algorithm);
  }
}
