package io.vertx.ext.auth;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public interface HashingAlgorithm {

  /**
   * return the symbolic name for the algorithm
   *
   * @return short id e.g.: sha512.
   */
  String id();

  /**
   * return the list of param names required for this algorithm.
   *
   * @return set of param names.
   */
  Set<String> params();

  /**
   * Algorithm specific implementation.
   *
   * @param params the algorithm parameters.
   * @param password the password to hash.
   * @return the hashed digest.
   */
  byte[] hash(Map<String, String> params, String password, byte[] salt);

  /**
   * Algorithm specific implementation.
   *
   * @param password the password to hash.
   * @return the hashed digest.
   */
  default byte[] hash(String password, byte[] salt) {
    return hash(Collections.emptyMap(), password, salt);
  }
}
