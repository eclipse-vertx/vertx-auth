package io.vertx.ext.auth.impl;

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.auth.HashingAlgorithm;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.HashString;

import java.util.HashMap;
import java.util.Map;

public class HashingStrategyImpl implements HashingStrategy {

  private static final Logger LOG = LoggerFactory.getLogger(HashingStrategyImpl.class);

  private final Map<String, HashingAlgorithm> algorithms = new HashMap<>();

  @Override
  public String hash(String id, Map<String, String> params, String salt, String password) {
    HashingAlgorithm algorithm = get(id);

    if (algorithm == null) {
      throw new RuntimeException(id +  " algorithm is not available.");
    }

    String hash = algorithm.hash(new HashString(id, params, salt), password);
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

    HashingAlgorithm algorithm = get(hashString.id());

    if (algorithm == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("No hash strategy for algorithm: " + hashString.id());
      }
      return false;
    }

    if (hashString.hash() == null) {
      return false;
    }

    String hasha = hashString.hash();
    String hashb = algorithm.hash(hashString, password);

    int diff = hasha.length() ^ hashb.length();
    for (int i = 0; i < hasha.length() && i < hashb.length(); i++) {
      diff |= hasha.charAt(i) ^ hashb.charAt(i);
    }

    return diff == 0;
  }

  @Override
  public HashingAlgorithm get(String id) {
    if (algorithms.containsKey(id)) {
      return algorithms.get(id);
    }
    return HashingAlgorithm.getById(id);
  }

  @Override
  public HashingStrategy put(String id, HashingAlgorithm algorithm) {

    if (algorithms.containsKey(id) || HashingAlgorithmHolder.containsId(id)) {
      LOG.warn("Existing algorithm: " + id + " will be replaced!");
    }

    algorithms.put(id, algorithm);
    return this;
  }
}
