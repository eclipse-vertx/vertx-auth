package io.vertx.ext.auth;

import java.util.Base64;
import java.util.Collections;
import java.util.Set;

public interface HashingAlgorithm {

  Base64.Decoder B64DEC = Base64.getDecoder();
  Base64.Encoder B64ENC = Base64.getEncoder();


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
  default Set<String> params()  {
    return Collections.emptySet();
  }

  /**
   * Algorithm specific implementation.
   *
   * @return the hashed digest.
   */
  String hash(HashString hashString, String password);

  /**
   * Should the encoded string use the default separator to split fields.
   * @return true by default.
   */
  default boolean needsSeparator() {
    return true;
  }
}
