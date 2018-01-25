package io.vertx.ext.auth;

import io.vertx.ext.auth.impl.HashingStrategyImpl;

import java.util.Map;
import java.util.ServiceLoader;

public interface HashingStrategy {

  static HashingStrategy load() {
    final HashingStrategyImpl strategy = new HashingStrategyImpl();
    ServiceLoader<HashingAlgorithm> serviceLoader = ServiceLoader.load(HashingAlgorithm.class);

    for (HashingAlgorithm algorithm : serviceLoader) {
      strategy.add(algorithm);
    }

    return strategy;
  }

  String hash(String id, Map<String, String> params, byte[] salt, String password);

  boolean verify(String hash, String password);
}
